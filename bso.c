#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <unistd.h>
#include <termios.h>
#include <sys/types.h>
#include <errno.h>

#include "bso.h"

EXPORT const char *d_userabort = "FATAL: Aborted by user";

EXPORT int d_query(const char *fmt, ...)
{
	char buf[2], obuf[] = {0x1b, 0x5b, 0x44, 0};
	int n, ret = -1;
	struct termios tcnew, tcold;
	va_list ap;

	if (tcgetattr(0, &tcnew)) {
		printf("FATAL: stdin not on a tty");
		goto out;
	}

	memcpy(&tcold, &tcnew, sizeof(tcold));

	tcnew.c_lflag &= ~(ECHO|ICANON|ISIG);

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	fflush(stdout);
	
	if (tcsetattr(0, TCSANOW, (const struct termios *) &tcnew)) {
		printf("FATAL: error setting terminal flags: %s", strerror(errno));
		goto out;
	}

	while ((n = read(0, &buf, 1)) > 0) {
		if (buf[0] >= 'A' && buf[0] <= 'z') {
			if (obuf[3] == '\0') {
				write(1, &buf, 1);
				obuf[3] = buf[0];
			} else {
				obuf[3] = buf[0];
				write(1, &obuf, 4);
			}
		} else if (buf[0] == 0x03 || buf[0] == 0x04 || buf[0] == 0x1c) {
			tcsetattr(0, TCSANOW, (const struct termios *) &tcold);
			goto out;
		} else if ((buf[0] == 0x7f || buf[0] == 0x08) && obuf[3]) {
			obuf[3] = '\0';
			write(1, "\x1b\x5b\x44 \x1b\x5b\x44", 7);
		} else if (buf[0] == '\r' || buf[0] == '\n') {
			if (tcsetattr(0, TCSANOW, (const struct termios *) &tcold))
				printf("WARNING: unable to reset terminal flags: %s,\n  try `stty sane' or `stty cooked'\n", strerror(errno));
			ret = obuf[3];
			goto out;
		}
	}

	if (n < 0) {
		printf("ERROR: error reading from stdin: %s\n", strerror(errno));
		if (tcsetattr(0, TCSANOW, (const struct termios *) &tcold))
			printf("WARNING: unable to reset terminal flags: %s,\n  try `stty sane' or `stty cooked'\n", strerror(errno));
		goto out;
	}

	out:
	putchar('\n');
	return ret;
}
