// SPDX-License-Identifier: GPL-2.0
/* BPF ring buffer implementation
 * Adapted from commit 457f44363a88 (kernel 5.8) for kernel 4.19:
 *   - replaced rqspinlock_t  → spinlock_t
 *   - removed dynptr variants (reserve_dynptr, submit_dynptr, discard_dynptr)
 *   - removed BPF_MAP_TYPE_USER_RINGBUF and user_ringbuf_map_ops
 *   - removed BTF_ID_LIST_SINGLE / map_btf_id
 *   - removed map_mem_usage, map_meta_equal callbacks
 *   - GFP_KERNEL_ACCOUNT kept (available since 4.12)
 */
#include <linux/bpf.h>
#include <linux/err.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/log2.h>
#include <linux/mm.h>
#include <linux/numa.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <uapi/linux/bpf.h>

#define RINGBUF_CREATE_FLAG_MASK	(BPF_F_NUMA_NODE)

/* The ring buffer is backed by a single contiguous vmalloc region.
 *
 * Kernel virtual layout:
 *   [header pages (RINGBUF_PGOFF pages)] [consumer page] [producer page] [data pages]
 *
 * Userspace mmap layout (two separate mmap() calls):
 *   pgoff=0, size=PAGE_SIZE           → consumer page  (r/w)
 *   pgoff=1, size=PAGE_SIZE+2*data_sz → producer page + data pages ×2 (r/o)
 *
 * The data pages are mapped twice so the consumer can read a record that wraps
 * around the end of the buffer without an extra copy.
 */
struct bpf_ringbuf {
	wait_queue_head_t	waitq;
	u64			mask;
	struct page		**pages;
	int			nr_pages;
	/* producer lock – also taken in NMI context, so irqsave variants */
	spinlock_t		spinlock ____cacheline_aligned_in_smp;
	/* consumer position – written by userspace consumer, read by kernel */
	unsigned long		consumer_pos __aligned(PAGE_SIZE);
	/* producer position – written by kernel, read by userspace consumer */
	unsigned long		producer_pos __aligned(PAGE_SIZE);
	/* ring buffer data area */
	char			data[] __aligned(PAGE_SIZE);
};

struct bpf_ringbuf_map {
	struct bpf_map		map;
	struct bpf_ringbuf	*rb;
};

/* Number of pages before consumer_pos in struct bpf_ringbuf */
#define RINGBUF_PGOFF	(offsetof(struct bpf_ringbuf, consumer_pos) >> PAGE_SHIFT)
/* consumer_pos page + producer_pos page */
#define RINGBUF_POS_PAGES	2

/* Header prepended to every ring buffer record (8 bytes total) */
struct bpf_ringbuf_hdr {
	u32	len;	/* bit31=BUSY, bit30=DISCARD, rest=data length */
	u32	pg_off;	/* page index of this record's page within data area */
};

/* ------------------------------------------------------------------ */
/*  Allocation / deallocation                                          */
/* ------------------------------------------------------------------ */

static struct bpf_ringbuf *bpf_ringbuf_alloc(size_t data_sz, int numa_node)
{
	struct bpf_ringbuf *rb;
	struct page **pages;
	size_t nr_meta_pages = RINGBUF_PGOFF + RINGBUF_POS_PAGES;
	size_t nr_data_pages = data_sz >> PAGE_SHIFT;
	size_t nr_pages = nr_meta_pages + nr_data_pages;
	long i;

	pages = bpf_map_area_alloc(nr_pages * sizeof(*pages), numa_node);
	if (!pages)
		return NULL;

	for (i = 0; i < nr_pages; i++) {
		pages[i] = alloc_pages_node(numa_node,
					    GFP_KERNEL_ACCOUNT |
					    __GFP_ZERO | __GFP_NOWARN |
					    __GFP_NORETRY,
					    0);
		if (!pages[i])
			goto err_free_pages;
	}

	rb = vmap(pages, nr_meta_pages + nr_data_pages, VM_MAP, PAGE_KERNEL);
	if (!rb)
		goto err_free_pages;

	rb->pages = pages;
	rb->nr_pages = nr_pages;
	init_waitqueue_head(&rb->waitq);
	spin_lock_init(&rb->spinlock);
	rb->mask = data_sz - 1;
	rb->consumer_pos = 0;
	rb->producer_pos = 0;

	return rb;

err_free_pages:
	for (i--; i >= 0; i--)
		__free_page(pages[i]);
	bpf_map_area_free(pages);
	return NULL;
}

static void bpf_ringbuf_free(struct bpf_ringbuf *rb)
{
	/* copy pointers before vunmap frees the kernel mapping */
	struct page **pages = rb->pages;
	int nr_pages = rb->nr_pages;
	int i;

	vunmap(rb);
	for (i = 0; i < nr_pages; i++)
		__free_page(pages[i]);
	bpf_map_area_free(pages);
}

/* ------------------------------------------------------------------ */
/*  bpf_map_ops callbacks                                              */
/* ------------------------------------------------------------------ */

static int ringbuf_map_alloc_check(union bpf_attr *attr)
{
	if (attr->map_flags & ~RINGBUF_CREATE_FLAG_MASK)
		return -EINVAL;
	if (attr->key_size || attr->value_size ||
	    !attr->max_entries ||
	    !PAGE_ALIGNED(attr->max_entries) ||
	    !is_power_of_2(attr->max_entries) ||
	    attr->max_entries > UINT_MAX / 2)
		return -EINVAL;
	return 0;
}

static struct bpf_map *ringbuf_map_alloc(union bpf_attr *attr)
{
	struct bpf_ringbuf_map *rb_map;

	rb_map = kzalloc(sizeof(*rb_map), GFP_USER);
	if (!rb_map)
		return ERR_PTR(-ENOMEM);

	bpf_map_init_from_attr(&rb_map->map, attr);

	rb_map->rb = bpf_ringbuf_alloc(attr->max_entries,
					bpf_map_attr_numa_node(attr));
	if (!rb_map->rb) {
		kfree(rb_map);
		return ERR_PTR(-ENOMEM);
	}

	return &rb_map->map;
}

static void ringbuf_map_free(struct bpf_map *map)
{
	struct bpf_ringbuf_map *rb_map =
		container_of(map, struct bpf_ringbuf_map, map);

	bpf_ringbuf_free(rb_map->rb);
	kfree(rb_map);
}

static void *ringbuf_map_lookup_elem(struct bpf_map *map, void *key)
{
	return ERR_PTR(-ENOTSUPP);
}

static int ringbuf_map_update_elem(struct bpf_map *map, void *key,
				   void *value, u64 flags)
{
	return -ENOTSUPP;
}

static int ringbuf_map_delete_elem(struct bpf_map *map, void *key)
{
	return -ENOTSUPP;
}

static int ringbuf_map_get_next_key(struct bpf_map *map, void *key,
				    void *next_key)
{
	return -ENOTSUPP;
}

/*
 * mmap() support.
 *
 * Userspace does two separate mmap() calls:
 *
 *   fd = bpf(BPF_MAP_CREATE, ...BPF_MAP_TYPE_RINGBUF...);
 *
 *   /* consumer page: read position written by consumer */
 *   consumer = mmap(NULL, PAGE_SIZE,
 *                   PROT_READ | PROT_WRITE, MAP_SHARED, fd,
 *                   0 * PAGE_SIZE);   /* pgoff = 0 */
 *
 *   /* producer page + data (twice for wraparound): written by kernel */
 *   producer = mmap(NULL, PAGE_SIZE + 2 * ring_size,
 *                   PROT_READ, MAP_SHARED, fd,
 *                   1 * PAGE_SIZE);   /* pgoff = 1 */
 */
static int ringbuf_map_mmap(struct bpf_map *map, struct vm_area_struct *vma)
{
	struct bpf_ringbuf_map *rb_map =
		container_of(map, struct bpf_ringbuf_map, map);
	struct bpf_ringbuf *rb = rb_map->rb;
	size_t data_sz = rb->mask + 1;
	size_t nr_data_pages = data_sz >> PAGE_SHIFT;
	pgoff_t pgoff = vma->vm_pgoff;
	size_t vma_sz = vma->vm_end - vma->vm_start;
	unsigned long uaddr;
	int i, err;

	if (pgoff == 0) {
		/* Consumer page: one page, read-write */
		if (vma_sz != PAGE_SIZE)
			return -EINVAL;
		return vm_insert_page(vma, vma->vm_start,
				      rb->pages[RINGBUF_PGOFF]);
	}

	if (pgoff == 1) {
		/* Producer page + data pages ×2: read-only */
		if (vma->vm_flags & VM_WRITE)
			return -EPERM;
		if (vma_sz != PAGE_SIZE + 2 * data_sz)
			return -EINVAL;

		/* VM_MIXEDMAP allows repeated vm_insert_page calls */
		vma->vm_flags |= VM_MIXEDMAP | VM_DONTEXPAND;
		uaddr = vma->vm_start;

		/* producer position page */
		err = vm_insert_page(vma, uaddr, rb->pages[RINGBUF_PGOFF + 1]);
		if (err)
			return err;
		uaddr += PAGE_SIZE;

		/* data pages – first copy */
		for (i = 0; i < nr_data_pages; i++, uaddr += PAGE_SIZE) {
			err = vm_insert_page(vma, uaddr,
					     rb->pages[RINGBUF_PGOFF + 2 + i]);
			if (err)
				return err;
		}

		/* data pages – second copy (for transparent wraparound) */
		for (i = 0; i < nr_data_pages; i++, uaddr += PAGE_SIZE) {
			err = vm_insert_page(vma, uaddr,
					     rb->pages[RINGBUF_PGOFF + 2 + i]);
			if (err)
				return err;
		}

		return 0;
	}

	return -EINVAL;
}

static __poll_t ringbuf_map_poll(struct bpf_map *map, struct file *filp,
				 struct poll_table_struct *pts)
{
	struct bpf_ringbuf_map *rb_map =
		container_of(map, struct bpf_ringbuf_map, map);
	struct bpf_ringbuf *rb = rb_map->rb;

	poll_wait(filp, &rb->waitq, pts);
	if (READ_ONCE(rb->consumer_pos) < READ_ONCE(rb->producer_pos))
		return EPOLLIN | EPOLLRDNORM;
	return 0;
}

const struct bpf_map_ops ringbuf_map_ops = {
	.map_alloc_check	= ringbuf_map_alloc_check,
	.map_alloc		= ringbuf_map_alloc,
	.map_free		= ringbuf_map_free,
	.map_mmap		= ringbuf_map_mmap,
	.map_poll		= ringbuf_map_poll,
	.map_lookup_elem	= ringbuf_map_lookup_elem,
	.map_update_elem	= ringbuf_map_update_elem,
	.map_delete_elem	= ringbuf_map_delete_elem,
	.map_get_next_key	= ringbuf_map_get_next_key,
};

/* ------------------------------------------------------------------ */
/*  Core ring-buffer record management                                 */
/* ------------------------------------------------------------------ */

/* Recover the bpf_ringbuf pointer from a data pointer returned by reserve.
 * The header at (data - HDR_SZ) stores pg_off: the page index of the record
 * within the data area.  Combined with the within-page offset from the
 * pointer itself we can reconstruct the exact offset and walk back to rb.
 */
static struct bpf_ringbuf *bpf_ringbuf_restore_from_rec(void *sample)
{
	struct bpf_ringbuf_hdr *hdr = sample - BPF_RINGBUF_HDR_SZ;
	unsigned long addr = (unsigned long)hdr;
	unsigned long page_off;

	/* offset of this record within the data area */
	page_off = (unsigned long)hdr->pg_off << PAGE_SHIFT;
	page_off += addr & (PAGE_SIZE - 1); /* within-page byte offset */

	/* rb->data is at (RINGBUF_PGOFF + RINGBUF_POS_PAGES) pages from rb */
	return (struct bpf_ringbuf *)
		(addr - (addr & (PAGE_SIZE - 1))   /* page start of hdr */
		 - hdr->pg_off * PAGE_SIZE         /* back to start of data area */
		 - (RINGBUF_PGOFF + RINGBUF_POS_PAGES) * PAGE_SIZE);
}

static void *__bpf_ringbuf_reserve(struct bpf_ringbuf *rb, u64 size)
{
	unsigned long cons_pos, prod_pos, new_prod_pos, flags;
	struct bpf_ringbuf_hdr *hdr;
	u32 len, pg_off;

	if (unlikely(size > UINT_MAX / 2))
		return NULL;

	/* total slot length: header + data, rounded to 8 bytes */
	len = round_up(size + BPF_RINGBUF_HDR_SZ, 8);
	if (len > rb->mask + 1)
		return NULL;

	/*
	 * Read the consumer position before taking the lock.
	 * smp_load_acquire pairs with smp_store_release in the consumer.
	 */
	cons_pos = smp_load_acquire(&rb->consumer_pos);

	if (in_nmi()) {
		if (!spin_trylock_irqsave(&rb->spinlock, flags))
			return NULL;
	} else {
		spin_lock_irqsave(&rb->spinlock, flags);
	}

	prod_pos = rb->producer_pos;
	new_prod_pos = prod_pos + len;

	/* not enough space? */
	if (new_prod_pos - cons_pos > rb->mask) {
		spin_unlock_irqrestore(&rb->spinlock, flags);
		return NULL;
	}

	hdr = (void *)rb->data + (prod_pos & rb->mask);
	pg_off = (prod_pos & rb->mask) >> PAGE_SHIFT;

	hdr->len    = size | BPF_RINGBUF_BUSY_BIT;
	hdr->pg_off = pg_off;

	/* make the header visible before advancing producer_pos */
	smp_store_release(&rb->producer_pos, new_prod_pos);

	spin_unlock_irqrestore(&rb->spinlock, flags);

	/* return pointer to the data area (after the header) */
	return (void *)hdr + BPF_RINGBUF_HDR_SZ;
}

static void bpf_ringbuf_commit(void *sample, u64 flags, bool discard)
{
	struct bpf_ringbuf_hdr *hdr;
	struct bpf_ringbuf *rb;
	u32 new_len;

	hdr = sample - BPF_RINGBUF_HDR_SZ;
	rb  = bpf_ringbuf_restore_from_rec(sample);

	new_len = hdr->len & ~BPF_RINGBUF_BUSY_BIT;
	if (discard)
		new_len |= BPF_RINGBUF_DISCARD_BIT;

	/* clear BUSY bit (and optionally set DISCARD) atomically */
	WRITE_ONCE(hdr->len, new_len);

	/* ensure the header update is visible before we check consumer */
	smp_mb();

	/* wake up consumers unless caller asked us not to */
	if (flags & BPF_RB_NO_WAKEUP)
		return;
	if ((flags & BPF_RB_FORCE_WAKEUP) ||
	    READ_ONCE(rb->consumer_pos) < READ_ONCE(rb->producer_pos))
		wake_up_all(&rb->waitq);
}

/* ------------------------------------------------------------------ */
/*  BPF helper implementations                                         */
/* ------------------------------------------------------------------ */

BPF_CALL_4(bpf_ringbuf_output, struct bpf_map *, map,
	   void *, data, u64, size, u64, flags)
{
	struct bpf_ringbuf_map *rb_map =
		container_of(map, struct bpf_ringbuf_map, map);
	void *rec;

	if (unlikely(flags & ~(BPF_RB_NO_WAKEUP | BPF_RB_FORCE_WAKEUP)))
		return -EINVAL;

	rec = __bpf_ringbuf_reserve(rb_map->rb, size);
	if (!rec)
		return -EAGAIN;

	memcpy(rec, data, size);
	bpf_ringbuf_commit(rec, flags, false /* submit */);
	return 0;
}

const struct bpf_func_proto bpf_ringbuf_output_proto = {
	.func		= bpf_ringbuf_output,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg4_type	= ARG_ANYTHING,
};

BPF_CALL_3(bpf_ringbuf_reserve, struct bpf_map *, map, u64, size, u64, flags)
{
	struct bpf_ringbuf_map *rb_map =
		container_of(map, struct bpf_ringbuf_map, map);

	if (unlikely(flags))
		return 0;

	return (unsigned long)__bpf_ringbuf_reserve(rb_map->rb, size);
}

const struct bpf_func_proto bpf_ringbuf_reserve_proto = {
	.func		= bpf_ringbuf_reserve,
	.ret_type	= RET_PTR_TO_ALLOC_MEM_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_CONST_ALLOC_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_ringbuf_submit, void *, sample, u64, flags)
{
	bpf_ringbuf_commit(sample, flags, false /* submit */);
	return 0;
}

const struct bpf_func_proto bpf_ringbuf_submit_proto = {
	.func		= bpf_ringbuf_submit,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_ALLOC_MEM,
	.arg2_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_ringbuf_discard, void *, sample, u64, flags)
{
	bpf_ringbuf_commit(sample, flags, true /* discard */);
	return 0;
}

const struct bpf_func_proto bpf_ringbuf_discard_proto = {
	.func		= bpf_ringbuf_discard,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_ALLOC_MEM,
	.arg2_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_ringbuf_query, struct bpf_map *, map, u64, flags)
{
	struct bpf_ringbuf *rb =
		container_of(map, struct bpf_ringbuf_map, map)->rb;

	switch (flags) {
	case BPF_RB_AVAIL_DATA:
		return READ_ONCE(rb->producer_pos) -
		       READ_ONCE(rb->consumer_pos);
	case BPF_RB_RING_SIZE:
		return rb->mask + 1;
	case BPF_RB_CONS_POS:
		return READ_ONCE(rb->consumer_pos);
	case BPF_RB_PROD_POS:
		return READ_ONCE(rb->producer_pos);
	default:
		return 0;
	}
}

const struct bpf_func_proto bpf_ringbuf_query_proto = {
	.func		= bpf_ringbuf_query,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
};
