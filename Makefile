NAME=ft_malcolm
CC=cc
FLAGS=-Wall -Werror -Wextra
SRC_FILES=$(wildcard *.c)
OBJ_FILES=$(SRC_FILES:.c=.o)
DEP_FILES=$(SRC_FILES:.c=.d)

all: $(NAME)

$(NAME): $(OBJ_FILES)
	$(CC) $(FLAGS) -o $@ $^

%.o: %.c
	$(CC) $(FLAGS) -MMD -c $< -o $@

clean:
	rm -f *.d
	rm -f *.o

fclean: clean
	rm -f $(NAME)

re: fclean all

-include $(DEPS)