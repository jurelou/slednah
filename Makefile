CC 		=	g++

# CFLAGS 	=	-W -Wall

CLINK	=	-lpsapi

NAME 	=	toto

SRCS	=	get_handles.cpp

OBJS	=	$(SRCS:.c=.o)

SRCS_SAFE	= get_handles_safe.cpp

OBJS_SAFE	=	$(SRCS_SAFE:.c=.o)

all:		$(OBJS)
			$(CC) $(CFLAGS) $(OBJS) -o $(NAME) $(CLINK)

safe:		$(OBJS_SAFE)
			$(CC) $(CFLAGS) $(OBJS_SAFE) -o $(NAME) $(CLINK)
