#!/usr/bin/env python

# You can use this script to create a test mbox with specific mail size
# distribution.
#
# Running the script creates a 'testmbox' output file in the current directory.

from email.mime.text import MIMEText
from email.utils import formatdate
import mailbox
import os
import random
import string
import tempfile

# Size distribution can be configured here. By default, a mbox with 5 mails of
# 10kB, 80kB, 150kB and 250kB each in a randomized order are created.
# ImapTest iterates through the mbox sequentially, so all randomness must be
# in the mbox file.
size_distribution = {
  10:    5,
  80:    5,
  150:   5,
  250:   5,
  15000: 0,
}

TEST_DOMAIN = "example.com"

mailfrom = f"sender@{TEST_DOMAIN}"
mailto = f"recipient@{TEST_DOMAIN}"
mbox_out = 'testmbox'
subject = 'Testmsg of %s kB'


def splitrow(string, linelen):
    step = linelen
    out = []
    for i in range(0, len(string), linelen):
        out.append(string[i:step])
        step += linelen
    return '\n' . join(out)


def main():
    date = formatdate()
    mails = []
    mbox_tmp = tempfile.mkstemp()
    os.close(mbox_tmp[0])
    mbox = mailbox.mbox(mbox_tmp[1])

    for key, val in size_distribution.items():
        for mail in range(0, val):
            mails.append(key)

    random.shuffle(mails)

    body_chars = string.ascii_letters + string.digits + " .-"
    mid_chars = string.ascii_letters + string.digits

    for val in mails:
        body = ''.join(random.choices(body_chars, k=val*1024))
        body = splitrow(body, 76)
        msg = MIMEText(body + '\n')
        msg.set_unixfrom('From %s %s' % (mailfrom, date))
        msg['Date'] = date
        msg['Subject'] = subject % val
        msg['To'] = mailto
        msg['From'] = mailfrom
        msg['Message-ID'] = '<' + ''.join(random.choices(mid_chars, k=24)) + f"@{TEST_DOMAIN}>"
        print(f"Creating message of size {val} KB")
        mbox.add(msg)

    mbox.close()

    with open(mbox_tmp[1], 'r') as tmpmbox:
        with open(mbox_out, 'w') as mbox:
            for line in tmpmbox:
                mbox.write(line.replace('\n', '\r\n'))

    os.unlink(mbox_tmp[1])

    print(f"Wrote mailbox to '{mbox_out}'")


if __name__ == "__main__":
    main()
