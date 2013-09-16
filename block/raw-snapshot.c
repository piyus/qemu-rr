#include <mydebug.h>
#include "qemu-common.h"
#include "block_int.h"
#include "block/raw-snapshot.h"

int raw_snapshot_create(BlockDriverState *bs, QEMUSnapshotInfo *sn_info)
{
  NOT_IMPLEMENTED();
}

int raw_snapshot_goto(BlockDriverState *bs, const char *snapshot_id)
{
  NOT_IMPLEMENTED();
}

int raw_snapshot_delete(BlockDriverState *bs, const char *snapshot_id)
{
  NOT_IMPLEMENTED();
}

int raw_snapshot_list(BlockDriverState *bs, QEMUSnapshotInfo **psn_tab)
{
  NOT_IMPLEMENTED();
}
