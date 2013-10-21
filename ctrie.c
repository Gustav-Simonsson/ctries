/*
 * @author gustav <gustav.simonsson@gmail.com>
 * @license: GNUBL 1.0
 *
 * Ctrie: Concurrent Tries with Non-Blocking Snapshots.
 *
 * Sources referenced in code comments:
 *
 * [1] Prokopec, A. et al. (2011)
 *     Cache-Aware Lock-Free Concurrent Hash Tries. Technical Report, 2011.
 * [2] Prokopec, A., Bronson N., Bagwell P., Odersky M. (2011)
 *     Concurrent Tries with Efficient Non-Blocking Snapshots
 * [3] http://en.wikipedia.org/wiki/Ctrie
 * [4] Scala ctrie implementation by  Aleksandar Prokopec (axel22)
 *     https://github.com/axel22/Ctries
 *
 * Notes:
 *
 * 1. The implementation is mainly based on [2]. As [2] describes the algorithm
 *    in functional-style pseudo-code, with recursive helper-functions, this
 *    imperative impl will naturally read in a different way.
 *
 * 2. As some node types (structs) can point to several node types, which is
 *    only known at run-time, we make use of void pointers and track the node
 *    types pointed to by these.
 *
 * 3. The C structs composing the ctrie are named after the types and data
 *    structures described in [2], with a few exceptions: the S-node struct is
 *    named kvnode, and the tombed inode is implemented as TODO
 *
 * Created : 19 May 2013 by gustav <gustav.simonsson@gmail.com>
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include "fnv.h"

#define ROOT_INODE 1
// node types switched on in insert/update/delete
#define GET_NODE_TYPE(options) (options & 7)
#define SET_NODE_TYPE(options, type) {options &= 248; options |= type;}
#define EMPTY_KVNODE 0
#define KVNODE 1
#define TOMBED_KVNODE 2
#define LNODE 3
#define CNODE 4
#define INODE 5

#define OK 0
#define RESTART 1
#define NOT_FOUND 2

// TODO: Think about which malloc to use, maybe Google's tcmalloc?
// TODO: maybe remove assert once ctrie is properly tested and stable?
#define CTRIE_MALLOC(n, t)         (malloc(         (n) * sizeof(t)))
#define CTRIE_REALLOC(ptr, n, t)   (realloc(ptr,    (n) * sizeof(t)))
#define CTRIE_MEMCPY(s1, s2, n, t) (memcpy(s1, s2,  (n) * sizeof(t)))
#define ZERO_ARRAY(a, size)        (memset((a), 0, size * sizeof((a)[0])))

/*
 * See chapter 3 in [2]. We use N bits in key hash as index for which
 * branch to follow. At the first level this is bit 0 .. N-1, at the next
 * level bit N to N*2 - 1, etc.
 *
 * We define a set of macros depending on whether the ctrie is built for 32 or
 * 64-bit archs. These include:
 *
 * 1. Number of bits of the hash key used at each level of the ctrie.
 * 2. C-Node children array length.
 * 3. Hash function to use.
 */
#ifdef CTRIE64

typedef uint64_t ctrie_int_t;
#define HASH_INDEX_LVL_BIT_CNT 6
//#define HASH_INDEX_MAX_BIT_CNT 58
#define HASH_INDEX_MAX_BIT_CNT 6
#define CNODE_ARRAY_LEN 64
// TODO: Try different hash functions and decide on optimal one for ctries
typedef Fnv32_t ctrie_hash_t;
#define HASH(key) (fnv_64a_buf(&(key), 8, 0))
#define HASH_INDEX(hash, bitcount) ((hash >> bitcount) & 63)
#define CAS(ptr, expected, desired)                        \
    __sync_bool_compare_and_swap_8((volatile void *) ptr,  \
                                   (uint64_t) expected,    \
                                   (uint64_t) desired)
#define SET_BRANCH_TYPES(a, n) (memcpy(a, (ctrie_int_t [64])           \
    {n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,  \
     n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n,n}, \
     64*sizeof(ctrie_int_t)))

#else

typedef uint32_t ctrie_int_t;
#define HASH_INDEX_LVL_BIT_CNT 5
//#define HASH_INDEX_MAX_BIT_CNT 27
#define HASH_INDEX_MAX_BIT_CNT 5
#define CNODE_ARRAY_LEN 32
typedef Fnv64_t ctrie_hash_t;
#define HASH(key) (fnv_32a_buf(&(key), 4, 0))
#define HASH_INDEX(hash, bitcount) ((hash >> bitcount) & 31)

#endif

/* struct definitions and struct types macros
 *
 * TODO: Optimize structs for minimal internal padding added by GCC on
 * modern x86 archs.
 */
struct ctrie
{
    ctrie_int_t options;
    void **root;
};

struct kvnode
{
    ctrie_int_t key;
    ctrie_int_t value;
};

struct cnode
{
    // TODO: maybe put inode gen in some bits in branch_type?
    ctrie_int_t branch_types[CNODE_ARRAY_LEN];
    struct kvnode branches[CNODE_ARRAY_LEN];
};

struct lnode
{
    int kvs_len;
    struct kvnode *kvs;
};

/*
 * Forward declarations
 */
ctrie_int_t compress_node(struct cnode *cn);
ctrie_int_t insert(struct ctrie *ct, ctrie_int_t key, ctrie_int_t value);
ctrie_int_t lookup(struct ctrie *ct, struct kvnode *lookup_kv);
ctrie_int_t delete(struct ctrie *ct, struct kvnode *delete_kv);
int delete_cn(struct cnode *cn);
/*
 * API
 */
struct ctrie *ct_new()
{
    struct ctrie *ct   = CTRIE_MALLOC(1,               struct ctrie);
    struct cnode *cn   = CTRIE_MALLOC(1,               struct cnode);
    void **iptr        = CTRIE_MALLOC(1,               void *);

    SET_BRANCH_TYPES(cn->branch_types, EMPTY_KVNODE);
    *iptr = cn;
    ct->root = iptr;
    return ct;
}

int ct_delete_ct(struct ctrie *ct)
{
    struct cnode *cn;
    int res;
    
    cn = (struct cnode *) *(ct->root);

    res = (delete_cn(cn) == OK) ? 0 : 1;

    free(ct->root);
    free(ct);

    return res;
}

int delete_cn(struct cnode *cn)
{
    struct cnode *cn2;
    struct lnode *ln;
    void **in_ptr;
    int i;

    for (i = 0; i < CNODE_ARRAY_LEN; i++) {
        switch (cn->branch_types[i]) {
        case CNODE:
            //printf("CT_DELETE: cnode\n");
            cn2 = (struct cnode *) *((void **) (cn->branches[i].key));
            delete_cn(cn2);
            break;
        case EMPTY_KVNODE:
            break;    
        case KVNODE: // freed when the cn itself is freed
            //printf("CT_DELETE: kvnode\n");
            break;
        case LNODE:
            //printf("CT_DELETE: lnode\n");
            in_ptr  = (void **) (cn->branches)[i].key;
            ln = (struct lnode *) *in_ptr;
            for (i = 0; (i < ln->kvs_len); i++) {
                free(&(ln->kvs)[i]);
            }
            free(ln);
            free(in_ptr);
            break;
        default:
            printf("CT_DELETE: default\n");
            return 1;
        }
    }
    free(cn);
    return 0;
}    


ctrie_int_t ct_insert(struct ctrie *ct, ctrie_int_t key, ctrie_int_t value)
{
    if (insert(ct, key, value) == RESTART) {
        return 1;
    } else {
        return 0;
    }
}

ctrie_int_t ct_lookup(struct ctrie *ct, struct kvnode *lookup_kv)
{
    int res = lookup(ct, lookup_kv);
    if (res == RESTART) {
        return 1;
    }
    if (res == NOT_FOUND) {
        return 1;
    }
    return 0;
}

ctrie_int_t ct_delete_kv(struct ctrie *ct, struct kvnode *delete_kv)
{
    int res = delete(ct, delete_kv);
    if (res == RESTART) {
        return 1;
    }
    if (res == NOT_FOUND) {
        return 1;
    }
    return 0;
}

ctrie_int_t insert(struct ctrie *ct, ctrie_int_t key, ctrie_int_t value)
{
    struct cnode *cn, *new_cn, *new_cn2;
    struct kvnode *kv, *new_kvs;
    struct lnode *ln, *new_ln;
    void *in_copy, *new_in, **in_ptr, **new_in_ptr;
    ctrie_hash_t key_hash;
    ctrie_int_t key_hash_bits,
        index, prev_lvl_index, present_kv_index,
        node_type;
    bool ln_update;
    int i;

    key_hash = HASH(key);
    key_hash_bits = 0;
    index = 0;
    node_type = CNODE;

    while (1) {
        switch (node_type) {
        case CNODE:
            in_ptr         = key_hash_bits == 0 ? ct->root :
            (void  **) (cn->branches)[index].key;
            in_copy        = *in_ptr;
            cn             = (struct cnode *) in_copy;
            index          = HASH_INDEX(key_hash, key_hash_bits);
            node_type      = GET_NODE_TYPE((cn->branch_types)[index]);
            key_hash_bits += HASH_INDEX_LVL_BIT_CNT;
            break;
        case EMPTY_KVNODE:
            new_cn = CTRIE_MALLOC(1, struct cnode);
            new_in = CTRIE_MALLOC(1, void *);

            *new_cn   = *cn;
            kv        = (struct kvnode *) &(new_cn->branches)[index];
            kv->key   = key;
            kv->value = value;
            SET_NODE_TYPE((new_cn->branch_types)[index], KVNODE);
            new_in = (void *) new_cn;
            if (CAS(in_ptr, in_copy, new_in)) {
                //free(&in_copy);
                free(cn);
                return OK;
            } else {
                free(new_cn);
                free(new_in);
                return RESTART;
            }
        case KVNODE:
            kv = (struct kvnode *) &(cn->branches)[index];
            if (kv->key == key && kv->value == value) {
                return OK; // only one value for each key
            }
            // Whether we do a update or create new cnode or lnode,
            // we always need a new cn and in for CAS
            new_cn = CTRIE_MALLOC(1, struct cnode);
            new_in = CTRIE_MALLOC(1, void *);
            *new_cn = *cn;
            kv = (struct kvnode *) &(new_cn->branches)[index];
            if (kv->key == key) { // update
                kv->value = value;
                new_in = (void *) new_cn;
                if (CAS(in_ptr, in_copy, new_in)) {
                    free(cn);
                    return OK;
                } else {
                    free(new_cn);
                    free(new_in);
                    return RESTART;
                }
            } else {
                if (key_hash_bits <= HASH_INDEX_MAX_BIT_CNT) {
                    /* See chapter 3.1 in [2]. Partial key hash collision; the part
                     * of the key hash used at this level collides with PRESENT kv,
                     * and we extend the ctrie with another level in the form of a
                     * NEW cnode. We put both PRESENT and NEW kvnode in the
                     * NEW cnode, and update ptr to PRESENT kvnode to NEW cnode.
                     */
                    new_in_ptr = CTRIE_MALLOC(1,               void **);
                    new_cn2    = CTRIE_MALLOC(1,               struct cnode);
                    SET_BRANCH_TYPES(new_cn2->branch_types, EMPTY_KVNODE);

                    prev_lvl_index   = index;
                    present_kv_index = HASH_INDEX(HASH(kv->key), key_hash_bits);
                    index            = HASH_INDEX(key_hash, key_hash_bits);

                    (new_cn2->branches)[index].key = key;
                    (new_cn2->branches)[index].value = value;
                    SET_NODE_TYPE((new_cn2->branch_types)[index], KVNODE);

                    (new_cn2->branches)[present_kv_index] = *kv;
                    SET_NODE_TYPE((new_cn2->branch_types)[present_kv_index],
                                  KVNODE);

                    *new_in_ptr = (void *) new_cn2;
                    (new_cn->branches)[prev_lvl_index].key =
                        (ctrie_int_t) new_in_ptr;
                    SET_NODE_TYPE((new_cn->branch_types)[prev_lvl_index],
                                  CNODE);
                    new_in = (void *) new_cn;
                    if (CAS(in_ptr, in_copy, new_in)) {
                        free(cn);
                        return OK;
                    } else {
                        free(new_cn);
                        free(new_cn2);
                        free(new_in);
                        free(new_in_ptr);
                        return RESTART;
                    }
                } else {
                    /* See chapter 3.3 in [2]. Full key hash collision; we cannot
                     * extend with another cnode as we are at the bottom of ctrie.
                     * Instead, we replace the present kvnode in the cnode
                     * with a new lnode holding the present AND new kvnode
                     */
                    new_in_ptr = CTRIE_MALLOC(1,  void **);
                    new_ln     = CTRIE_MALLOC(1,  struct lnode);
                    new_kvs =    CTRIE_MALLOC(2,  struct kvnode);

                    new_kvs[0]                = *kv;
                    new_kvs[1].key            = key;
                    new_kvs[1].value          = value;
                    new_ln->kvs               = new_kvs;
                    new_ln->kvs_len           = 2;
                    *new_in_ptr               = (void *) new_ln;
                    (new_cn->branches)[index].key = (ctrie_int_t) new_in_ptr;
                    SET_NODE_TYPE((new_cn->branch_types)[index], LNODE);
                    new_in = (void *) new_cn;

                    if (CAS(in_ptr, in_copy, new_in)) {
                        free(cn);
                        return OK;
                    } else {
                        free(new_cn);
                        free(new_in);
                        free(new_in_ptr);
                        free(new_ln);
                        return RESTART;
                    }
                }
            }
        case LNODE:
            in_ptr  = (void **) (cn->branches)[index].key;
            in_copy = *in_ptr;
            ln      = (struct lnode *) in_copy;

            new_in = CTRIE_MALLOC(1, void *);
            new_ln = CTRIE_MALLOC(1, struct lnode);
            new_kvs = CTRIE_MALLOC(ln->kvs_len, struct kvnode);

            CTRIE_MEMCPY(new_kvs, ln->kvs, ln->kvs_len, struct kvnode);
            new_ln->kvs     = new_kvs;
            new_ln->kvs_len = ln->kvs_len;
            ln_update       = false;

            for (i = 0; (i < new_ln->kvs_len); i++) {
                if ((new_ln->kvs)[i].key == key) {
                    //printf("INSERT: updating lnode\n");
                    (new_ln->kvs)[i].value = value; // update
                    ln_update = true;
                }
            }
            // No matching key in lnode found for update; extend lnode.
            //printf("insert kv key/value: %d %d\n", kv_to_insert->key, kv_to_insert->value);
            if (!ln_update) {
                new_ln->kvs_len++;
                new_ln->kvs = CTRIE_REALLOC(new_ln->kvs, new_ln->kvs_len,
                                            struct kvnode);
                (new_ln->kvs)[new_ln->kvs_len - 1].key   = key;
                (new_ln->kvs)[new_ln->kvs_len - 1].value = value;
            }
            new_in = (void *) new_ln;
            if (CAS(in_ptr, in_copy, new_ln)) {
                //for (i = 0; i < ln->kvs_len; i++) {
                //free((ln->kvs[i]));
                //}
                free(ln->kvs);
                free(ln);
                return OK;
            } else {
                // TODO: frees
                return RESTART;
            }
        default:
            return 1;
        }
    }
}

ctrie_int_t lookup(struct ctrie *ct, struct kvnode *lookup_kv)
{
    struct cnode *cn;
    struct kvnode *kv;
    struct lnode *ln;
    void *in_copy, **in_ptr;
    ctrie_hash_t key_hash;
    ctrie_int_t key_hash_bits, index, node_type;
    int i;

    key_hash = HASH(lookup_kv->key);
    key_hash_bits = 0;
    index = 0;
    node_type = CNODE;

    while (1) {
        switch (node_type) {
        case CNODE:
            in_ptr         = key_hash_bits == 0 ?
                                 ct->root :
                                 (void  **) (cn->branches)[index].key;
            in_copy        = *in_ptr;
            cn             = (struct cnode *) in_copy;
            index          = HASH_INDEX(key_hash, key_hash_bits);
            node_type      = GET_NODE_TYPE((cn->branch_types)[index]);
            key_hash_bits += HASH_INDEX_LVL_BIT_CNT;
            break;
        case EMPTY_KVNODE:
            return NOT_FOUND;
        case KVNODE:
            kv = (struct kvnode *) &(cn->branches)[index];
            if (kv->key == lookup_kv->key) {
                lookup_kv->value = kv->value;
                return OK;
            } else {
                return NOT_FOUND;
            }
        case LNODE:
            in_ptr  = (void **) (cn->branches)[index].key;
            in_copy = *in_ptr;
            ln = (struct lnode *) in_copy;
            for (i = 0; (i < ln->kvs_len); i++) {
                if ((ln->kvs)[i].key == lookup_kv->key) {
                    lookup_kv->value = (ln->kvs)[i].value;
                    return OK;
                }
            }
            return NOT_FOUND;
        default:
            return NOT_FOUND;
        }
    }
}

ctrie_int_t delete(struct ctrie *ct, struct kvnode *delete_kv)
{
    struct cnode *cn, *new_cn;
    struct kvnode *kv;
    struct lnode *ln;
    void *in_copy, *in_copy2, *new_in, **in_ptr, **in_ptr2;
    ctrie_hash_t key_hash;
    ctrie_int_t key_hash_bits, index, node_type;
    int i;

    key_hash = HASH(delete_kv->key);
    key_hash_bits = 0;
    index = 0;
    node_type = CNODE;

    while (1) {
        switch (node_type) {
        case CNODE:
            in_ptr         = key_hash_bits == 0 ?
                                 ct->root :
                                 (void  **) (cn->branches)[index].key;
            in_copy        = *in_ptr;
            cn             = (struct cnode *) in_copy;
            index          = HASH_INDEX(key_hash, key_hash_bits);
            node_type      = GET_NODE_TYPE((cn->branch_types)[index]);
            key_hash_bits += HASH_INDEX_LVL_BIT_CNT;
            break;
        case EMPTY_KVNODE:
            return NOT_FOUND;
        case KVNODE:
            kv = (struct kvnode *) &(cn->branches)[index];
            if (kv->key == delete_kv->key) {
                new_cn = CTRIE_MALLOC(1, struct cnode);
                new_in = CTRIE_MALLOC(1, void *);

                *new_cn = *cn;
                SET_NODE_TYPE((new_cn->branch_types)[index], EMPTY_KVNODE);
                delete_kv->value = kv->value;
                new_in = (void *) new_cn;
                if (CAS(in_ptr, in_copy, new_in)) {
                    free(cn);
                    return OK;
                } else {
                    free(new_cn);
                    free(new_in);
                    return RESTART;
                }
            } else {
                printf("DELETE: Key not found: found kvnode not matching\n");
                return NOT_FOUND;
            }
        case LNODE:
            in_ptr2  = (void **) (cn->branches)[index].key;
            in_copy2 = *in_ptr2;
            ln = (struct lnode *) in_copy2;
            for (i = 0; (i < ln->kvs_len); i++) {
                if ((ln->kvs)[i].key == delete_kv->key) {
                    new_in = CTRIE_MALLOC(1, void *);
                    delete_kv->value = (ln->kvs)[i].value;
                    if (ln->kvs_len > 2) {
                        // Copy struct mem instead of pointer?
                        (ln->kvs)[i] = (ln->kvs)[ln->kvs_len - 1];
                        ln->kvs_len--;
                        new_in = (void *) ln;
                        if (CAS(in_ptr2, in_copy2, new_in)) {
                            //free(&(ln->kvs)[ln->kvs_len]);
                            return OK;
                        } else {
                            free(new_in);
                            return RESTART;
                        }
                    } else {
                        new_cn = CTRIE_MALLOC(1, struct cnode);
                        *new_cn = *cn;
                        i = i == 1 ? 0 : 1;
                        (new_cn->branches)[index].key   = (ln->kvs)[i].key;
                        (new_cn->branches)[index].value = (ln->kvs)[i].value;
                        SET_NODE_TYPE((new_cn->branch_types)[index], KVNODE);
                        new_in = (void *) new_cn;
                        if (CAS(in_ptr, in_copy, new_in)) {
                            //i = i == 1 ? 1 : 0;
                            //free(ln->kvs)[i]);
                            free(cn);
                            free(ln);
                            free(in_ptr2);
                            return OK;
                        } else {
                            free(new_cn);
                            free(new_in);
                            return RESTART;
                        }
                    }
                }
            }
            printf("Delete: Key not found: no matching kv in lnode\n");
            //printf("DELETE: %d %d\n", (int) key, (int) in_ptr);
            return NOT_FOUND;
        default:
            printf("DELETE: default case hit in delete? %d %d \n",
                   (int) node_type, (int) delete_kv->key);
            return NOT_FOUND;
        }
    }
}

/*
 * Tests
 */
void run_unit_tests()
{
    //     printf("DEBUG 6\n");
    printf("\nRunning unit tests:\n\n");

    struct ctrie *ct = ct_new();
    struct kvnode *kv1 = CTRIE_MALLOC(1, struct kvnode);

    ctrie_int_t key_count =
        //CNODE_ARRAY_LEN *
        //CNODE_ARRAY_LEN *
        CNODE_ARRAY_LEN *
        CNODE_ARRAY_LEN * 16 +
        1;
    printf("Insert for %d keys: ", (int) key_count);
    ctrie_int_t key, value, i;
    int res;
    for (i=0; i<key_count; i++) {
        key = i;
        value = (i * 2) + 100;
        res = ct_insert(ct, key, value);
        assert(res == 0);
    }
    printf("OK\n");

    printf("Lookup for %d keys: ", (int) key_count);
    for (i=0; i<key_count; i++) {
        kv1->key = i;
        res = ct_lookup(ct, kv1);
        //printf("Unit tests: lookup kv1 key, value: %d, %d \n ", kv1->key, kv1->value);
        assert(res == 0);
        assert(kv1->value == (i * 2) + 100);
    }
    printf("OK\n");
    printf("Update & Lookup for %d keys: ", (int) key_count);
    for (i=0; i<key_count; i++) {
        kv1 = CTRIE_MALLOC(1, struct kvnode);
        key = i;
        value = (i * 3) + 222;
        res = ct_insert(ct, key, value);
        assert(res == 0);
    }
    for (i=0; i<key_count; i++) {
        kv1->key = i;
        res = ct_lookup(ct, kv1);
        //printf("Unit tests: lookup kv1 key, value: %d, %d \n ", kv1->key, kv1->value);
        assert(res == 0);
        assert(kv1->value == (i * 3) + 222);
    }
    printf("OK\n");
    printf("Delete & Lookup for %d keys: ", (int) key_count);
    for (i=0; i<key_count; i++) {
        kv1->key = i;
        res = ct_delete_kv(ct, kv1);
        assert(res == 0);
        //assert(kv1->value != (i * 3) + 222);
    }
    for (i=0; i<key_count; i++) {
        kv1->key = i;
        res = ct_lookup(ct, kv1);
        assert(res != 0);
    }

    res = ct_delete_ct(ct);
    assert(res == 0);
    free(kv1);
    printf("OK\n");
    printf("\nEnd unit tests\n");
}

int main()
{
    run_unit_tests();
    return 0;
}
