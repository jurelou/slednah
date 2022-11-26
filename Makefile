CC 		=	g++

CFLAGS 	=	-O2 -Wall -Wextra -Wpedantic
 
# SECFLAGS = -fstack-protector-strong -fstack-clash-protection -fPIE

CLINK	=	-lpsapi

NAME 	=	slednah

SRCS_UNSAFE	=	get_handles_unsafe.cpp

OBJS_UNSAFE	=	$(SRCS_UNSAFE:.c=.o)

SRCS_SAFE	= get_handles_safe.cpp

OBJS_SAFE	=	$(SRCS_SAFE:.c=.o)

all:		$(OBJS_SAFE)
			$(CC) $(CFLAGS) $(OBJS_SAFE) -o $(NAME) $(CLINK)

unsafe:		$(OBJS_UNSAFE)
			$(CC) $(CFLAGS) $(OBJS_UNSAFE) -o $(NAME) $(CLINK)
