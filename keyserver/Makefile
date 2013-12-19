# Makefile: builds the kssl_server and kssl_testclient
#
# Copyright (c) 2013 CloudFlare, Inc.

# Turn on absolutely all warnings and turn them into errors

CFLAGS += -g -Wall -Wextra -Wno-unused-parameter -Werror

# Link against OpenSSL and libev

LDLIBS := -lcrypto -lssl -lev

# This Makefile makes use of the GNU Make Standard Library project
# which can be found at http://gmsl.sf.net/

GMSL_DIR := gmsl/
include $(GMSL_DIR)/gmsl

# Macros for automatically making directories using marker files.
# http://www.cmcrossroads.com/ask-mr-make/6936-making-directories-in-gnu-make
# for rationale.

marker = $1.f
make_dir = $(eval $1.f: ; @mkdir -p $$(dir $$@) ; touch $$@)

TMP := tmp/

OBJ := o/
SERVER_OBJS := $(addprefix $(OBJ)kssl_,server.o helpers.o core.o private_key.o log.o)
TEST_OBJS := $(addprefix $(OBJ)kssl_,helpers.o testclient.o log.o)
OBJS := $(SERVER_OBJS) $(TEST_OBJS)
EXECS := $(addprefix $(OBJ)kssl_,server testclient)

.PHONY: all clean test run kill
all: $(OBJ) $(EXECS)
clean: ; @rm -rf $(OBJ)

$(call make_dir,$(TMP))

# Note the use of a # comment at the end of VALGRIND_COMMAND to ensure
# that there is a trailing space

VALGRIND_COMMAND :=
ifeq ($(VALGRIND),1)
VALGRIND_LOG := valgrind.log
VALGRIND_COMMAND := valgrind --leak-check=yes --log-file=$(VALGRIND_LOG) --show-reachable=yes #
endif

PORT := $(shell perl free-port.pl)
PID_FILE := $(TMP)kssl_server.pid
SERVER_LOG := $(TMP)kssl_server.log
CA_FILE := CA/cacert.pem
ifneq ($(wildcard $(PID_FILE)),)
PID := $(shell cat $(PID_FILE))
run: ; @echo kssl_server running as PID $(PID)
kill:
	@kill $(PID)
	@rm -f $(PID_FILE)
else
run: all $(call marker,$(TMP))
ifeq ($(VALGRIND),1)
	@rm -f $(VALGRIND_LOG)
endif
	@$(VALGRIND_COMMAND)$(OBJ)kssl_server --port=$(PORT) --server-cert=server-cert/cert.pem --server-key=server-cert/key.pem --private-key-directory=keys --cipher-list=ECDHE-RSA-AES128-SHA256:AES128-GCM-SHA256:RC4:HIGH:!MD5:!aNULL:!EDH --ca-file=$(CA_FILE) --pid-file=$(PID_FILE) --silent --num-processes=4 &> $(SERVER_LOG) $&
ifeq ($(VALGRIND),1)
	@echo $$! > $(PID_FILE)
endif

kill: ;
endif

# Note that sub-makes are used here for the kill and run targets
# because the definition of those targets changes depending on the
# presence or absence of the kssl_server.pid file (see above) and thus
# it's necessary to restart make for them to do the right thing.

test: all
	@$(MAKE) --no-print-directory kill
	@$(MAKE) --no-print-directory run VALGRIND=$(VALGRIND) PORT=$(PORT)
	@perl -e 'while (!-e "$(PID_FILE)") { sleep(1); }'
	@$(OBJ)kssl_testclient --port=$(PORT) --private-key=keys/private.key --client-cert=client-cert/cert.pem --client-key=client-cert/key.pem --ca-file=$(CA_FILE) $(DEBUG)
ifeq ($(VALGRIND),1)
	@$(MAKE) --no-print-directory kill
	@echo valgrind log in $(VALGRIND_LOG)
endif

# ABOVE: when running the test suite with valgrind we need the
# kssl_server to terminate; hence the extra $(MAKE) kill at the end

$(OBJ):
	@mkdir -p $@

$(OBJ)kssl_server: $(SERVER_OBJS) ; @$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@
$(OBJ)kssl_testclient: $(TEST_OBJS) ; @$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@

$(OBJ)%.o: %.c ; @$(COMPILE.c) $(CFLAGS) $(OUTPUT_OPTION) $<

$(OBJ)kssl_server.o: kssl.h
$(OBJ)kssl_testclient.o: kssl.h
