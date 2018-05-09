TARGET = router

all: $(TARGET)

CFALGS = -g -Wall

CC = gcc
LD = gcc

SRCS = main.c RTable.c
OBJS = $(patsubst %.c,%.o,$(SRCS))

$(OBJS) : %.o : %.c
	$(CC) -c $(CFALGS) $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(CFALGS) $(OBJS) -o $(TARGET)

clean:
	rm -f *.o $(TARGET)
