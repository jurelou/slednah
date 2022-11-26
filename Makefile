CC 		=	g++

# CFLAGS 	=	-W -Wall

CLINK	=	-lpsapi

NAME 	=	toto

SRCS	=	get_handles.cpp

OBJS	=	$(SRCS:.c=.o)

all:		$(NAME)

$(NAME):	$(OBJS)
			$(CC) $(CFLAGS) $(OBJS) -o $(NAME) $(CLINK)