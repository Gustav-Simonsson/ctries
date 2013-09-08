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
 *    imperative impl will naturally read in a different way. In particular,
 *    the delete (remove) function described in chapter 3.2 [2] is quite
 *    different since it makes use of the contraction and compression functions
 *    on arbitrary number of C-nodes. Whereas in a functional impl these can be
 *    tracked by the call stack, here we keep a history of traversed nodes
 *    in a void pointer array
 *
 * 2. As some node types (structs) can point to several node types, which is
 *    only known at run-time, we make use of void pointers and track the node
 *    types pointed to by these.
 *
 * 3. The C structs composing the ctrie are named after the types and data
 *    structures described in [2], with a few exceptions: the S-node struct is
 *    named kvnode, and the tombed inode is here implemented as regular inode,
 *    with its type tracked in the above cnode.
 *
 * Created : 19 May 2013 by gustav <gustav.simonsson@gmail.com>
 */

#include <stdlib.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include "fnv.h"

/* Configuration and helper macros
 *
 */
#define SET_ROOT_NODE(opts) (opts |= 1) // set first bit
// set node type bits
#define SET_NODE_TYPE(opts, type) {opts &= 241; opts |= type;} 
#define IS_ROOT_INODE(in_opts) (in_opts & 1)
#define CHILD_NODE(in_opts) (in_opts & 14)
#define ROOT_INODE 1
// node types switched on in insert/update/delete
// integer values of bit 2-4
#define CHILD_EMPTY 0
#define CHILD_INODE 2
#define CHILD_CNODE 4
#define CHILD_LNODE 6
#define CHILD_KVNODE 8
#define CHILD_TOMBED_KVNODE 10

// ctrie options bitmap
#define NO_OPTS 0
#define READONLY 1

// misc internal function return codes
#define NOTFOUND 2
#define CONTRACTION 0
#define NO_CONTRACTION 1

#define OK 0
#define RESTART 1

// TODO: Think about which malloc to use, maybe Google's tcmalloc?
// TODO: maybe remove assert once ctrie is properly tested and stable?
#define CTRIE_MALLOC(n, t) ({void *x = malloc((n) * sizeof(t)); \
                        assert(x && "Ctrie malloc failed!"); \
                        x;})

#define ZERO_ARRAY(a, size) (memset((a), 0, size * sizeof((a)[0])))

// TODO: Can we benefit from a more relaxed model?
#define CAS_MEM_BARRIER __ATOMIC_SEQ_CST
#define CAS(ptr, expected, desired) \
    __atomic_compare_exchange(ptr, expected, desired, false, \
                              CAS_MEM_BARRIER, CAS_MEM_BARRIER)

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
#define HASH_INDEX_LEVEL_BIT_COUNT 6
#define HASH_INDEX_MAX_BIT_COUNT 58
#define CNODE_ARRAY_LEN 64
// TODO: Try different hash functions and decide on optimal one for ctries
typedef Fnv32_t ctrie_hash_t;
#define HASH(key) (fnv_64a_buf(&(key), 8, 0))
#define HASH_INDEX(hash, bitcount) ((hash >> bitcount) & 63)

#else

typedef uint32_t ctrie_int_t;
#define HASH_INDEX_LEVEL_BIT_COUNT 5
//#define HASH_INDEX_MAX_BIT_COUNT 27
#define HASH_INDEX_MAX_BIT_COUNT 5
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
    struct inode *root;
};

struct inode
{
    // As inode consists of one 32-bit or 64-bit int and one void pointer,
    // it is two words in size on both 32-bit and 64-bit archs, enabling use
    // of double-word CAS on the entire inode struct.
    ctrie_int_t opts;
    void *mn; // Mainnode; points to either cnode or lnode
};

struct cnode
{
    char branch_types[CNODE_ARRAY_LEN];  // inode, kvnode or tombed kvnode
    void *branches[CNODE_ARRAY_LEN];
};

struct kvnode
{
    ctrie_int_t key;
    ctrie_int_t value;
};

struct lnode
{
    struct kvnode kvn;
    struct lnode *next;
};

/*
 * Forward declarations
 */
ctrie_int_t compress_node(struct cnode *cn);
ctrie_int_t delete(struct cnode *cn, ctrie_int_t kv_pos);
ctrie_int_t insert(struct kvnode *kv_to_insert, struct ctrie *ct);

/*
 * API
 */
struct ctrie *new_ct()
{
    struct ctrie *ct = CTRIE_MALLOC(1, struct ctrie);
    struct inode *in = CTRIE_MALLOC(1, struct inode);
    struct cnode *cn = CTRIE_MALLOC(1, struct cnode);

    ZERO_ARRAY(cn->branch_types, CNODE_ARRAY_LEN);
    SET_ROOT_NODE(in->opts);
    SET_NODE_TYPE(in->opts, CHILD_CNODE);
    in->mn = cn;
    ct->options = NO_OPTS;
    ct->root = in;
    return ct;
}

ctrie_int_t ct_insert(struct kvnode *kv_to_insert, struct ctrie *ct)
{
    int res;
    do {
        res = insert(kv_to_insert, ct);
    } while (res == RESTART);
    return 0;
}

ctrie_int_t insert(struct kvnode *kv_to_insert, struct ctrie *ct)
{
    ctrie_hash_t key_hash;
    ctrie_int_t key_hash_bits;
    ctrie_int_t index, prev_level_index, present_kv_index;
    struct kvnode *kv;
    struct cnode *cn, *new_cn, cn_copy;
    struct inode *in, *new_in, in_copy;
    struct lnode *ln, *new_ln, *ln_head;
    ctrie_int_t child_type; // node type of node void pointer
    void *node;

    key_hash = HASH(kv_to_insert->key);
    key_hash_bits = 0;
    index = 0;
    node = ct->root->mn;
    child_type = CHILD_CNODE;

    while (1) {
        switch (child_type) {
        case CHILD_INODE:
            in = ((struct inode *) node);
            in_copy = *in;
            node = in_copy.mn;
            child_type = CHILD_NODE(in_copy.opts);
            break;
        case CHILD_CNODE:
            cn = ((struct cnode *) node);
            cn_copy = *cn;
            index = HASH_INDEX(key_hash, key_hash_bits);
            node = (cn_copy.branches)[index];
            key_hash_bits += HASH_INDEX_LEVEL_BIT_COUNT;
            child_type = (cn_copy.branch_types)[index];
            break;
        case CHILD_EMPTY:
            new_in = CTRIE_MALLOC(1, struct inode);
            new_cn = CTRIE_MALLOC(1, struct cnode);
            *new_in = in_copy;
            *new_cn = cn_copy;
            (new_cn->branches)[index] = kv_to_insert;
            new_cn->branch_types[index] = CHILD_KVNODE;
            new_in->mn = new_cn;
            CAS(in, &in_copy, new_in);
            return 0;
        case CHILD_KVNODE:
            kv = (struct kvnode *) node;
            if (kv->key == kv_to_insert->key) { // key exists in ctrie; update
                kv->value = kv_to_insert->value;
                return 0;
            } else {
                /* See chapter 3.3 in [2]. Full key hash collision; we cannot
                 * extend with another cnode as we are at the bottom of ctrie.
                 * Instead, we replace the PRESENT kvnode in the ctrie
                 * with a NEW inode holding a NEW lnode holding the PRESENT
                 * kvnode. Then, we break and let the generic lnode
                 * (traversing new inode) case handle the insertion of
                 * the NEW kvnode into the NEW lnode.
                 */
                if (key_hash_bits > HASH_INDEX_MAX_BIT_COUNT) {
                    //printf("INSERT: full key hash coll; creating lnode\n");
                    //printf("kv key: %d kv value: %d insert kv key: %d\n", kv->key, kv->value, kv_to_insert->key);
                    new_in = CTRIE_MALLOC(1, struct inode);
                    new_ln = CTRIE_MALLOC(1, struct lnode);
                    new_ln->kvn = *kv;
                    new_ln->next = NULL;
                    new_in->mn = new_ln;
                    SET_NODE_TYPE(new_in->opts, CHILD_LNODE);
                    (cn->branches)[index] = new_in;
                    cn->branch_types[index] = CHILD_INODE;
                    node = new_in;
                    child_type = CHILD_INODE;
                    break;
                }
                /* See chapter 3.1 in [2]. Partial key hash collision; the part
                 * of the key hash used at this level collides with PRESENT kv,
                 * and we extend the ctrie with another level in the form of a
                 * NEW inode holding a NEW cnode. We put both PRESENT and NEW
                 * kvnode in the NEW cnode, and replace ptr to PRESENT kvnode
                 * with ptr to NEW inode.
                 */
                //printf("INSERT: partial key hash coll; creating i and cnode\n");
                new_cn = CTRIE_MALLOC(1, struct cnode);
                new_in = CTRIE_MALLOC(1, struct inode);
                prev_level_index = index;
                present_kv_index = HASH_INDEX(HASH(kv->key), key_hash_bits);
                index = HASH_INDEX(key_hash, key_hash_bits);
                ZERO_ARRAY(new_cn->branch_types, CNODE_ARRAY_LEN);
                (new_cn->branches)[index] = kv_to_insert;
                (new_cn->branches)[present_kv_index] = kv;
                new_cn->branch_types[index] = CHILD_KVNODE;
                new_cn->branch_types[present_kv_index] = CHILD_KVNODE;
                new_in->mn = new_cn;
                SET_NODE_TYPE(new_in->opts, CHILD_CNODE);
                (cn->branches)[prev_level_index] = new_in;
                cn->branch_types[prev_level_index] = CHILD_INODE;
                return 0;
            }
        case CHILD_LNODE:
            ln = ln_head = (struct lnode *) node;
            do {
                if (ln->kvn.key == kv_to_insert->key) {
                    //printf("INSERT: updating lnode\n");
                    ln->kvn.value = kv_to_insert->value; // insert becomes update
                    return 0;
                } else {
                    ln = ln->next;
                }
            } while (ln != NULL);
            // No matching key in lnode found for update; extend lnode.
            //printf("INSERT: extending lnode\n");
            //printf("insert kv key/value: %d %d\n", kv_to_insert->key, kv_to_insert->value);
            new_ln = CTRIE_MALLOC(1, struct lnode);
            new_ln->kvn = *kv_to_insert;
            new_ln->next = ln_head;
            in->mn = new_ln;
            return 0;
        default:
            printf("TODO: default case hit in insert?\n\n");
            return 1;
        }
    }
}

// TODO: extract traversal from insert/lookup/delete into one traversal fun?
ctrie_int_t ct_lookup(struct kvnode *lookup_kv, struct ctrie *ct)
{
    ctrie_hash_t key_hash;
    ctrie_int_t key_hash_bits;
    ctrie_int_t index;
    struct kvnode *kv;
    struct cnode *cn;
    struct inode *in;
    struct lnode *ln;
    ctrie_int_t child_type; // node type of node void pointer
    void *node;

    key_hash = HASH(lookup_kv->key);
    key_hash_bits = 0;
    index = 0;
    node = ct->root->mn;
    child_type = CHILD_CNODE;

    while (1) {
        switch (child_type) {
        case CHILD_INODE:
            in = ((struct inode *) node);
            node = in->mn;
            child_type = CHILD_NODE(in->opts);
            break;
        case CHILD_CNODE:
            cn = ((struct cnode *) node);
            index = HASH_INDEX(key_hash, key_hash_bits);
            node = (cn->branches)[index];
            child_type = (cn->branch_types)[index];
            key_hash_bits += HASH_INDEX_LEVEL_BIT_COUNT;
            break;
        case CHILD_KVNODE:
            kv = (struct kvnode *) node;
            if (kv->key == lookup_kv->key) {
                lookup_kv->value = kv->value;
                return 0;
            } else {
                printf("LOOKUP: Key not found: found kvnode not matching\n");
                printf("kv key: %d kv value: %d lookup kv key: %d\n", (int) kv->key, (int) kv->value, (int) lookup_kv->key);
                return 1;
            }
            break;
        case CHILD_LNODE:
            ln = (struct lnode *) node;
            do {
                if (ln->kvn.key == lookup_kv->key) {
                    //printf("LOOKUP: Key found in lnode\n");
                    //printf("kv key: %d kv value: %d lookup kv key: %d\n", ln->kvn.key, ln->kvn.value, lookup_kv->key);
                    lookup_kv->value = ln->kvn.value;
                    return 0;
                } else {
                    ln = ln->next;
                }
            } while (ln != NULL);
            printf("LOOKUP: Key not found: no matching kv in lnode\n");
            return 1;
        default:
            //printf("LOOKUP: default case hit in lookup? %d %d \n", child_type, lookup_kv->key);
            return 1;
        }
    }
}

// TODO: extract traversal from insert/lookup/delete into one traversal fun?
ctrie_int_t ct_delete(struct kvnode *delete_kv, struct ctrie *ct)
{
    ctrie_hash_t key_hash;
    ctrie_int_t key_hash_bits;
    ctrie_int_t index;
    struct kvnode *kv;
    struct cnode *cn;
    struct inode *in;
    struct lnode *ln, *ln_head, *ln_prev;
    ctrie_int_t child_type; // node type of node void pointer
    void *node;

    key_hash = HASH(delete_kv->key);
    key_hash_bits = 0;
    index = 0;
    node = ct->root->mn;
    child_type = CHILD_CNODE;

    while (1) {
        switch (child_type) {
        case CHILD_INODE:
            in = ((struct inode *) node);
            node = in->mn;
            child_type = CHILD_NODE(in->opts);
            break;
        case CHILD_CNODE:
            cn = ((struct cnode *) node);
            index = HASH_INDEX(key_hash, key_hash_bits);
            node = (cn->branches)[index];
            child_type = (cn->branch_types)[index];
            key_hash_bits += HASH_INDEX_LEVEL_BIT_COUNT;
            break;
        case CHILD_KVNODE:
            kv = (struct kvnode *) node;
            if (kv->key == delete_kv->key) {
                delete(cn, index);
                return 0;
            } else {
                printf("Delete: Key not found: found kvnode not matching\n");
                return 1;
            }
            break;
        case CHILD_LNODE:
            ln = ln_prev = ln_head = (struct lnode *) node;
            do {
                if (ln->kvn.key == delete_kv->key) {
                    // lnode has 2 kvs; delete kv and move remaining kv upstairs
                    if (ln == ln_head && ln->next->next == NULL) {
                        (cn->branch_types)[index] = CHILD_KVNODE;
                        kv = (struct kvnode *) &((struct lnode *) ln->next)->kvn;
                        (cn->branches)[index] = kv;
                        free(ln);
                        free(in);
                        return 0;
                    }
                    if (ln_head->next == ln && ln->next == NULL) {
                        (cn->branch_types)[index] = CHILD_KVNODE;
                        kv = (struct kvnode *) &(ln_head->kvn);
                        (cn->branches)[index] = kv;
                        free(ln);
                        free(in);
                        return 0;
                    }
                    // lnode has 3 kvs; delete kv and retain lnode
                    ln_prev->next = ln->next;
                    free(ln);
                    return 0;
                } else {
                    ln_prev = ln;
                    ln = ln->next;
                }
            } while (ln != NULL);
            printf("Delete: Key not found: no matching kv in lnode\n");
            return 1;
        default:
            printf("Delete: TODO: default case hit? wtf?\n\n");
            return 1;
        }
    }
}

/*
 * Internal functions
 */
ctrie_int_t delete(struct cnode *cn,
                   ctrie_int_t kv_pos)
{
    struct cnode *new_cn;
    //struct inode *in;
    struct kvnode *kv;

    new_cn = CTRIE_MALLOC(1, struct cnode);
    *new_cn = *cn;
    kv = ((struct kvnode *) (new_cn->branches)[kv_pos]);
    (new_cn->branch_types)[kv_pos] = CHILD_EMPTY;
    // TODO: move free when changing to CAS
    free(kv);
    // TODO: Use CAS and return RESTART on failed CAS
    *cn = *new_cn;
    return 0;
}

ctrie_int_t contract_node(struct cnode *parent_cn, struct cnode *cn,
                          ctrie_int_t in_pos)
{
    struct inode *in;
    struct inode new_in;
    int i, non_kvnode_count, kvnode_pos;

    non_kvnode_count = 0;
    kvnode_pos = 0;

    for (i = 0; (i < CNODE_ARRAY_LEN); i++) {
        if (((cn->branch_types)[i]) == CHILD_KVNODE) {
            kvnode_pos = i;
        } else {
            non_kvnode_count++;
        }
    }
    if (non_kvnode_count == (CNODE_ARRAY_LEN - 1)) {
        in = (struct inode *) (parent_cn->branches)[in_pos];
        new_in = *in;
        new_in.mn = (cn->branches)[kvnode_pos];
        SET_NODE_TYPE(new_in.opts, CHILD_TOMBED_KVNODE);
        // TODO: replace copy with CAS on in & new_in
        *in = new_in;
        // TODO: move free cn to caller, if CAS OK
        free(cn);
        return CONTRACTION;
    }
    return NO_CONTRACTION;
}

ctrie_int_t compress_node(struct cnode *cn)
{
    struct cnode new_cn;
    struct inode *in;
    int i;
    int compress_count;

    new_cn = *cn;
    compress_count = 0;

    for (i = 0; (i < CNODE_ARRAY_LEN); i++) {
        if (((cn->branch_types)[i]) == CHILD_INODE) {
            in = ((struct inode *) (cn->branches)[i]);
            if (CHILD_NODE(in->opts) == CHILD_TOMBED_KVNODE) {
                (cn->branch_types)[i] = CHILD_KVNODE;
                (cn->branches)[i] = in->mn;
                // TODO: move free to caller, if CAS was OK ?
                free(in);
                compress_count++;
            }
        }
    }
    if (compress_count > 0) {
        // TODO: Use CAS and return RESTART on failed CAS
        *cn = new_cn;
    }
    return 0;
}

//ctrie_int_t delete_and_contract(struct inode *in, struct kvnode *kv,
//                              ctrie_int_t pos)
//{
    //struct cnode new_cn;
//  return 0;
//}

/*
 * Tests
 */
void run_unit_tests()
{
    printf("\nRunning unit tests:\n\n");

    struct ctrie *ct = new_ct();
    struct kvnode *kv1;
    ctrie_int_t key_count =
        //CNODE_ARRAY_LEN *
        //CNODE_ARRAY_LEN *
        //CNODE_ARRAY_LEN *
        //CNODE_ARRAY_LEN * 1 +
        1;

    printf("Insert for %d keys: ", (int) key_count);
    ctrie_int_t i;
    ctrie_int_t n;
    for (i=0; i<key_count; i++) {
        kv1 = CTRIE_MALLOC(1, struct kvnode);
        kv1->key = i;
        kv1->value = (i * 2) + 100;
        n = ct_insert(kv1, ct);
        assert(n == 0);
    }
    printf("OK\n");

    printf("Lookup for %d keys: ", (int) key_count);
    int lookup_res = 1;
    kv1 = CTRIE_MALLOC(1, struct kvnode);
    for (i=0; i<key_count; i++) {
        kv1->key = i;
        lookup_res = ct_lookup(kv1, ct);
        //printf("Unit tests: lookup kv1 key, value: %d, %d \n ", kv1->key, kv1->value);
        assert(lookup_res == 0);
        assert(kv1->value == (i * 2) + 100);
    }
    printf("OK\n");

    printf("Update & Lookup for %d keys: ", (int) key_count);
    for (i=0; i<key_count; i++) {
        kv1 = CTRIE_MALLOC(1, struct kvnode);
        kv1->key = i;
        kv1->value = (i * 3) + 222;
        n = ct_insert(kv1, ct);
        assert(n == 0);
    }
    for (i=0; i<key_count; i++) {
        kv1->key = i;
        lookup_res = ct_lookup(kv1, ct);
        //printf("Unit tests: lookup kv1 key, value: %d, %d \n ", kv1->key, kv1->value);
        assert(lookup_res == 0);
        assert(kv1->value == (i * 3) + 222);
    }
    printf("OK\n");

    printf("Delete & Lookup for %d keys: ", (int) key_count);
    int delete_res;
    for (i=0; i<key_count; i++) {
        kv1->key = i;
        delete_res = ct_delete(kv1, ct);
        assert(delete_res == 0);
        //assert(kv1->value != (i * 3) + 222);
    }
    for (i=0; i<key_count; i++) {
        kv1->key = i;
        lookup_res = ct_lookup(kv1, ct);
        assert(lookup_res != 0);
    }
    printf("OK\n");

    printf("\nEnd unit tests\n");
}

int main()
{
    run_unit_tests();
    return 0;
}
