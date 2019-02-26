CC = gcc
RM = rm -f
AR = ar

WARN = -Wall

INC = -I$(SRC)/common
BIN = $(SRC)/bin
CMN = $(SRC)/common

CFLAGS = $(INC) $(WARN) -g
