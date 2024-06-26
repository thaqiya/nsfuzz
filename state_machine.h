#ifndef __STATEMACHINE_H
#define __STATEMACHINE_H

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"
#include "khash.h"

// Initialize a hash table with u32 key and value is of type state_info_t
// state hash value => state_info_t
KHASH_INIT(hms, u32, struct state_info_t *, 1, kh_int_hash_func, kh_int_hash_equal)

/* State Selection Policy */

// enum STATE_SELECTION_POLICY {

//      /* 00 */ RANDOM_SELECTION, 
//      /* 01 */ ROUND_ROBIN,
//      /* 02 */ FAVOR
// };

struct transfer_edge_info_t {

    // u32 from_id, to_id;
    u32 from_state_hash_id, to_state_hash_id;
    u32 edge_hit_count;
    struct queue_entry *queue, *queue_top;
    u32 queued_paths, queued_id;
    struct transfer_edge_info *next_edge;
};

struct state_info_t {
   
    u32 state_hash_id;         /* state id */

    // u32 queued_paths, current_entry;

    struct transfer_edge_info *first_edge, *last_edge;

    u32 edge_num;

    // u32 state_hit_count;

    u32 score;               /* current score of the state */

    /* AFLNet state_info_t other attrs */
    // u32 id;                  /* state id */

    u32 fuzzs;               /* Total number of fuzzs (i.e., inputs generated) 只计算在common_fuzz_stuff后触发的状态情况，如果该状态被触发则++*/
    u32 paths;               /* total number of paths exercising this state 计算所有run_target（common_fuzz_stuff和dry_run）时触发的path数 */
    u32 paths_discovered;    /* total number of new paths that have been discovered when this state is targeted/selected state被选择为target state时，新触发的path数*/
    u32 selected_times;      /* total number of times this state has been targeted/selected */
    
    u32 selected_seed_index; /* the recently selected seed index */

    void **seeds;            /* keeps all seeds reaching this state -- can be casted to struct queue_entry* */

    u32 seeds_count;         /* total number of seeds, it must be equal the size of the seeds array */
};


struct state_machine {

    khash_t(hms) *khms_states;     /* Hash table mapping state hash to state_info_t */

    u32 *state_ids;                /* An array mapping state id (from 0, increase with append sequence) to state hash */

    u32 state_num;

    // u32 transfer_edge_num;

    // u32 round_robin_index;           // used when using ROUND_ROBIN policy

    // struct state_info_t **state_ids; // init is NULL

    // u8 *visited;                     // mark the state whether has been visited 标记节点是否被访问过(被加入路径)
    // u32 *next;                       // mark the next state of index in a path 记录各节点在路径中的下一节点
    // u32 *state_stack;                // state stack, to record the path 使用数组实现栈的功能，用于记录当前走的路径
    // u32 path_len;
};

// for state ids (e.g. 3),
// state_info_t *state = state_machine->state_ids[3];
// transfer_edge_info *edge = state->first_edge;
// state_info_t *next_state = state_machine->state_ids[edge->to_state_index]

struct transfer_path {
    struct transfer_edge_info **path_edge;
    u32 path_size;
    u32 path_length;
};

void state_append(struct state_machine *FSM, u32 new_state_hash);

void edge_append(struct state_machine *FSM, u32 current_state_hash, u32 new_state_hash, u8 *out_dir);

u8 is_new_state(struct state_machine *FSM, u32 state_hash);

u8 is_new_edge(struct state_machine *FSM, u32 current_state_hash, u32 new_state_hash);

struct state_info_t *get_state_by_hash(struct state_machine *FSM, u32 state_hash);

u32 get_state_index(struct state_machine *FSM, u32 state_hash);

struct transfer_edge_info *get_edge_by_hash(struct state_machine *FSM, u32 current_state_hash, u32 new_state_hash);

struct state_info_t *select_target_state(struct state_machine *FSM);

struct transfer_edge_info *get_next_transfer_edge(struct state_machine *FSM, struct state_info_t *cur_state, struct state_info_t *target_state);

struct transfer_edge_info *get_next_potential_edge(struct state_machine *FSM, u32 state_index);

#endif /* __STATEMACHINE_H */