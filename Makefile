CC=gcc
CFLAGS=-std=gnu99 -Wall -W -Wextra -pedantic -g -Werror
RM=rm -f
NAME=dns

all: $(NAME)

$(NAME): $(NAME).c
	$(CC) -o $(NAME) $(NAME).c $(CFLAGS)

.PHONY: clean, run, test
clean:
	$(RM) *.o $(NAME)
run: all
	./$(NAME) -r -p 53 -s 8.8.8.8 www.fit.vutbr.cz
	
test: all
	./$(NAME) -r -s kazi.fit.vutbr.cz dns.google.com
	./$(NAME) -s 8.8.8.8 ukazka argumentu adresy www.google.com
	./$(NAME) -x -r -s 8.8.8.8 147.229.9.23
	./$(NAME) spatne argumenty