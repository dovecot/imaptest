#ifndef CHECKPOINT_H
#define CHECKPOINT_H

void clients_checkpoint(struct mailbox_storage *storage);
void checkpoint_neg(struct mailbox_storage *storage);

#endif
