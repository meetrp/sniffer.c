#
# The MIT License (MIT)
#
# Copyright (c) 2015 Rp
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#


#
# Primary outputs
BIN                     = sniffer

#
# default directories
INCLUDE_DIR             = include
BUILD_DIR               = build
SRC_DIR                 = src

DEFAULT_LIB_PATH        ?= /usr/local/lib

#
# commonly used tools
CC                      ?= gcc

#
# project related CFLAGS
CFLAGS                  = -Wall
CFLAGS                  += -Werror
CFLAGS                  += -g

#
# project related LDFLAGS
LDFLAGS                 = -L $(DEFAULT_LIB_PATH)

#
# project related IFLAGS
IFLAGS                  = -I $(INCLUDE_DIR)



#
# By default do not install
.DEFAULT_GOAL := all

all: bin

clean:
	rm -rf $(BUILD_DIR)

bin: $(addprefix $(BUILD_DIR)/, $(BIN))

#
# always make these
.PHONY: all clean


#
# Define the project files
#   1. Get all the .c files in the given 'src' folder.
#   2. For every src/.c, the object file is build/src/.o
SRC_OBJ_DIR = $(addprefix $(BUILD_DIR)/,                        \
                $(SRC_DIR)                                      \
            )
SRC_FILES   = $(foreach sdir,                                   \
                $(SRC_DIR),                                     \
                $(wildcard $(sdir)/*.c)                         \
            )
SRC_OBJS    = $(patsubst $(SRC_DIR)/%.c,                        \
                $(SRC_OBJ_DIR)/%.o,                             \
                $(SRC_FILES)                                    \
            )

#
# build the main binary
$(BUILD_DIR)/$(BIN): src_settings $(SRC_OBJS)
	$(eval LINK_OBJS = $(filter-out $<,$^))
	$(CC) $(CFLAGS) $(LINK_OBJS) -o $@ $(LDFLAGS)
#
# setup for compilation
src_settings:
	@mkdir -p $(SRC_OBJ_DIR)

#
# compile the object files.
$(BUILD_DIR)/%.o: %.c
	$(CC) $(IFLAGS) $(CFLAGS) -c $< -o $@
