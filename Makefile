CC      ?= gcc
CFLAGS  ?= -O3 -Wall -Wextra -std=gnu11
CPPFLAGS += -Isrc -MMD -MP
LDLIBS   = -lpthread -lm

BUILD   := build
APP     := cpuminer
TESTBIN := run_tests

SRC_APP := src/main.c src/miner.c src/sha256.c src/sha256d_ni.c \
           src/stratum.c src/gbt.c src/target.c src/util.c src/cJSON.c
OBJ_APP := $(patsubst src/%.c,$(BUILD)/%.o,$(SRC_APP))

SRC_LIB := src/miner.c src/sha256.c src/sha256d_ni.c src/target.c src/util.c
OBJ_TEST := $(patsubst src/%.c,$(BUILD)/%.o,$(SRC_LIB)) $(BUILD)/test_vectors.o

all: $(APP)

$(APP): $(OBJ_APP)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(TESTBIN): $(OBJ_TEST)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

$(BUILD)/%.o: tests/%.c | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

$(BUILD):
	mkdir -p $(BUILD)

test: $(TESTBIN)
	./$(TESTBIN)

clean:
	rm -rf $(BUILD) $(APP) $(TESTBIN)

-include $(wildcard $(BUILD)/*.d)

.PHONY: all test clean
