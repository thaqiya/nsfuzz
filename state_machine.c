#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "state_machine.h"
#include "khash.h"

extern FILE *fp_debug, *fp_req_seq;

void state_append(struct state_machine *FSM, u32 new_state_hash) {

    // FSM->state_ids = (struct state_info_t **)ck_realloc(FSM->state_ids, (FSM->state_num + 1) * sizeof(struct state_info_t *));

    struct state_info_t *new_state = (struct state_info_t *)ck_alloc(sizeof(struct state_info_t));

    new_state->state_hash_id = new_state_hash;

    // memset(new_state->virgin_bits, 255, MAP_SIZE);

    new_state->seeds = NULL;
    new_state->seeds_count = 0;

    new_state->fuzzs = 0;
    new_state->paths_discovered = 0;
    new_state->selected_times = 0;
    new_state->selected_seed_index = 0;

    // new_state->queue = NULL;
    // new_state->queue_top = NULL;
    // new_state->queue_cur = NULL;
    // new_state->queued_paths = 0;

    new_state->first_edge = NULL;
    new_state->edge_num = 0;

    // new_state->state_hit_count = 0;
    new_state->score = 1;
    
    int ret;
    khint_t k;

    k = kh_put(hms, FSM->khms_states, new_state_hash, &ret);
    
    kh_value(FSM->khms_states, k) = new_state;

    FSM->state_ids = (u32 *)ck_realloc(FSM->state_ids, (FSM->state_num + 1) * sizeof(u32));

    FSM->state_ids[FSM->state_num++] = new_state_hash;

    // FSM->state_num++;
    // k = kh_put(hms, khms_states, prevStateID, &discard);

    // FSM->state_ids[FSM->state_num++] = new_state_hash;

    // if (FSM->state_num == 1) {
    //     FSM->visited = (u8 *)ck_alloc(sizeof(u8));
    //     FSM->next = (u32 *)ck_alloc(sizeof(u32));
    //     FSM->state_stack = (u32 *)ck_alloc(sizeof(u32));
    // } else {
    //     // printf("state num: %d\n", FSM->state_num);
    //     FSM->visited = ck_realloc(FSM->visited, sizeof(u8) * FSM->state_num);
    //     FSM->next = ck_realloc(FSM->next, sizeof(u32) * FSM->state_num);
    //     FSM->state_stack = ck_realloc(FSM->state_stack, sizeof(u32) * FSM->state_num);
    // }
}

// edge must be appended after the current state and new state 
// void edge_append(struct state_machine *FSM, u32 current_state_hash, u32 new_state_hash, u8 *out_dir) {
//     struct state_info_t *from_state = get_state_by_hash(FSM, current_state_hash);
//     if (!from_state) FATAL("current state does not exist in FSM");

//     struct state_info_t *to_state = get_state_by_hash(FSM, new_state_hash);
//     if (!to_state) FATAL("new state does not exist in FSM");

//     struct transfer_edge_info_t *new_edge = (struct transfer_edge_info_t *)ck_alloc(sizeof(struct transfer_edge_info_t));
//     new_edge->from_id = from_state->id;
//     new_edge->from_state_hash = from_state->state_hash_id;
//     new_edge->to_id = to_state->id;
//     new_edge->to_state_hash = to_state->state_hash_id;

//     new_edge->edge_hit_count = 0;

//     new_edge->queue = NULL;
//     new_edge->queue_top = NULL;
//     new_edge->queued_paths = 0;
//     new_edge->queued_id = 0;

//     struct transfer_edge_info_t *edge = from_state->first_edge;
//     if (edge) {
//         while(edge->next_edge)
//             edge = edge->next_edge;
//         edge->next_edge = new_edge;
//     } else
//         from_state->first_edge = new_edge;
//     new_edge->next_edge = NULL;

//     u8 *fpath = alloc_printf("%s/queue/FSM/edges/%u->%u", out_dir, current_state_hash, new_state_hash);
//     if (mkdir(fpath, 0700)) PFATAL("Unable to create '%s'", fpath);
//     new_edge->fpath = fpath;

//     FSM->transfer_edge_num++;
// }

/* check whether a new state; 
   return value: 1 => new state; 0 => state exists 
*/

u8 is_new_state(struct state_machine *FSM, u32 state_hash) {

    khint_t k;

    k = kh_get(hms, FSM->khms_states, state_hash);

    if (k != kh_end(FSM->khms_states)) //state exists
        return 0;

    return 1;

    // for (int i = 0; i < FSM->state_num; i++) {
    //     if (FSM->state_ids[i]->state_hash_id == state_hash)
    //         return 0;
    // }
    // return 1;
}

// u8 is_new_edge(struct state_machine *FSM, u32 current_state_hash, u32 new_state_hash) {
//     struct state_info_t *from_state = get_state_by_hash(FSM, current_state_hash);
//     if (!from_state) FATAL("current state does not exist in FSM");
//     struct transfer_edge_info_t *edge = from_state->first_edge;
//     while (edge) {
//         if (edge->to_state_hash == new_state_hash)
//             return 0;
//         edge = edge->next_edge;
//     }
//     return 1;
// }

struct state_info_t *get_state_by_hash(struct state_machine *FSM, u32 state_hash) {

    struct state_info_t *state = NULL;

    khint_t k;

    k = kh_get(hms, FSM->khms_states, state_hash);

    if (k != kh_end(FSM->khms_states)) 
      state = kh_val(FSM->khms_states, k);

    return state;

}

/* Get state index in the state hash IDs list, given a state hash */
u32 get_state_index(struct state_machine *FSM, u32 state_hash) {
    u32 index = 0;
    for (index = 0; index < FSM->state_num; index++) {
        if (FSM->state_ids[index] == state_hash)
            break;
    }
    return index;
}

// struct transfer_edge_info_t *get_edge_by_hash(struct state_machine *FSM, u32 current_state_hash, u32 new_state_hash) {
//     struct state_info_t *from_state = get_state_by_hash(FSM, current_state_hash);
//     if (!from_state) FATAL("current state does not exist in FSM");
//     struct transfer_edge_info_t *edge = from_state->first_edge;
//     while (edge) {
//         if (edge->to_state_hash == new_state_hash)
//             return edge;
//         edge = edge->next_edge;
//     }
//     return NULL;
// }

/*
    Once find a path from cur_state to target_state, return the next transfer edge.
    return NULL means can not get a good edge.
    the cur_state must not be equal with target_state
*/
// struct transfer_edge_info_t *get_next_transfer_edge(struct state_machine *FSM, struct state_info_t *cur_state, struct state_info_t *target_state) {
//     // maintain a stack, once could find a path, return the next transfer edge (if the edge has queue)
    
//     u32 state_num = FSM->state_num;

//     memset(FSM->visited, 0, sizeof(u8) * state_num);
//     memset(FSM->next, -1, sizeof(u32) * state_num);
//     memset(FSM->state_stack, -1, sizeof(u32) * state_num);
//     s32 top = 0; //表示path_record数组最大索引，来标识当前的栈顶位置

//     // u8 visited[state_num + 1];

//     // u32 next[state_num];        // mark the next state of index in a path 记录各节点在路径中的下一节点

//     // u32 state_stack[state_num]; // state stack, to record the path 使用数组实现栈的功能，用于记录当前走的路径

//     // for (u32 i = 0; i < state_num; i++) {
//     //     visited[i] = 0;
//     //     next[i] = -1;
//     //     state_stack[i] = -1;
//     // }
//     // top = 0;

//     u32 start_index = cur_state->id;
//     u32 end_index = target_state->id;
    
//     //start state push in stack
//     FSM->state_stack[top] = start_index;
//     FSM->visited[start_index] = 1;

//     u32 cur_id;
//     struct transfer_edge_info_t *edge;

//     while (top >= 0) {
//         cur_id = FSM->state_stack[top];
//         if (cur_id == end_index) { //已走到结束节点，输出完整路径

// #ifdef TEST
//             printf("%d -> %d : ", start_index, end_index);
//             for (u32 i = 0; i <= top; i++) {
//                 if (i == 0)
//                     printf("<%d> %c", FSM->state_stack[i], FSM->state_ids[FSM->state_stack[i]]->id);
//                 else
//                     printf(" >> <%d> %c", FSM->state_stack[i], FSM->state_ids[FSM->state_stack[i]]->id);
//             }
//             printf("\n");
// #endif // DEBUG

//             //return next edge
//             struct transfer_edge_info_t *ret_edge = FSM->state_ids[start_index]->first_edge;
//             while(ret_edge->to_id != FSM->state_stack[1]) 
//                 ret_edge = ret_edge->next_edge;
//             //indeed have transfer edge queue entry
//             if (ret_edge->queued_paths)
//                 return ret_edge;

//             //结束节点出栈
//             FSM->visited[cur_id] = 0;
//             FSM->state_stack[top] = -1;
//             FSM->next[cur_id] = -1;
//             top--;
//         } else {
//             edge = get_next_potential_edge(FSM, cur_id);
//             if (edge) {
//                 //有可走的路径下一跳，当前节点入栈
//                 FSM->next[cur_id] = edge->to_id;
//                 // path_next[cur_vex] = p->idx;
//                 top++;
//                 FSM->state_stack[top] = edge->to_id;
//                 // path_record[top] = p->idx;
//                 FSM->visited[edge->to_id] = 1;
//                 // visited[p->idx] = 1;
//             } else {
//                 //没有可走的路径下一跳，当前节点出栈
//                 FSM->visited[cur_id] = 0;
//                 // visited[cur_vex] = 0;
//                 FSM->state_stack[top] = -1;
//                 // path_record[top] = -1;
//                 top--;
//                 FSM->next[cur_id] = -1;
//                 // path_next[cur_vex] = -1;
//             }
//         }
//     }
//     return NULL;
// }

// struct transfer_edge_info_t *get_next_potential_edge(struct state_machine *FSM, u32 id) {

//     struct transfer_edge_info_t *edge;

//     edge = FSM->state_ids[id]->first_edge;

//     while (edge) {
//         if (FSM->visited[edge->to_id]) { // has been in the path
//             edge = edge->next_edge;
//         } else {
//             // 未被路径访问过
//             if (FSM->next[id] == -1) {
//                 while (edge && FSM->visited[edge->to_id])
//                     edge = edge->next_edge;
//                 return edge;
//             }
//             //被上一次路径访问过
//             else if (FSM->next[id] == edge->to_id) {
//                 edge = edge->next_edge;
//                 while (edge && FSM->visited[edge->to_id])
//                     edge = edge->next_edge;
//                 return edge;
//             }
//             //被以前的路径访问过
//             else {
//                 edge = edge->next_edge;
//             }
//         }
//     }
//     return NULL;
// }
