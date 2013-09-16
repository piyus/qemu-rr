#ifndef BLOCK_RAW_SNAPSHOT_H
#define BLOCK_RAW_SNAPSHOT_H

int raw_snapshot_create(BlockDriverState *bs, QEMUSnapshotInfo *sn_info);
int raw_snapshot_goto(BlockDriverState *bs, const char *snapshot_id);
int raw_snapshot_delete(BlockDriverState *bs, const char *snapshot_id);
int raw_snapshot_list(BlockDriverState *bs, QEMUSnapshotInfo **psn_tab);

#endif  /* block/raw-snapshot.h */
