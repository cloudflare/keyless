# Makefile: builds the keyserver and testclient
#
# Copyright (c) 2013 CloudFlare, Inc.

# Turn on absolutely all warnings and turn them into errors

CFLAGS += -g -Wall -Wextra -Wno-unused-parameter -Werror

# Link against OpenSSL and libev

LDLIBS := -lcrypto -lssl -lev

OBJ := o/
SERVER_OBJS := $(addprefix $(OBJ)kssl_,server.o helpers.o core.o private_key.o log.o)
TEST_OBJS := $(addprefix $(OBJ)kssl_,helpers.o testclient.o log.o)
OBJS := $(SERVER_OBJS) $(TEST_OBJS)
EXECS := $(addprefix $(OBJ),kssl_server kssl_testclient)

.PHONY: all clean test run kill
all: $(OBJ) $(EXECS)
clean: ; @rm -rf $(OBJ)

# Note the use of a # comment at the end of VALGRIND_COMMAND to ensure
# that there is a trailing space

VALGRIND_COMMAND :=
ifeq ($(VALGRIND),1)
VALGRIND_LOG := valgrind.log
VALGRIND_COMMAND := valgrind --leak-check=yes --log-file=$(VALGRIND_LOG) #
endif

PORT := 6543
PID_FILE := keyserver.pid
CA_FILE := CA/cacert.pem
ifneq ($(wildcard $(PID_FILE)),)
PID := $(shell cat $(PID_FILE))
run: ; @echo keyserver running as PID $(PID)
kill:
	@kill $(PID)
	@rm -f $(PID_FILE)
else
run: all
	@$(VALGRIND_COMMAND)$(OBJ)keyserver --port=$(PORT) --server-cert=server-cert/cert.pem --server-key=server-cert/key.pem --private-key-directory=keys --cipher-list=ECDHE-RSA-AES128-SHA256:AES128-GCM-SHA256:RC4:HIGH:!MD5:!aNULL:!EDH --ca-file=$(CA_FILE) --pid-file=$(PID_FILE) --silent --num-processes=4 &
ifeq ($(VALGRIND),1)
	@echo $$! > $(PID_FILE)
endif

kill: ; @echo keyserver not running
endif

# Note that sub-makes are used here for the kill and run targets
# because the definition of those targets changes depending on the
# presence or absence of the keyserver.pid file (see above) and thus
# it's necessary to restart make for them to do the right thing.

test: all
	@$(MAKE) --no-print-directory kill
	@$(MAKE) --no-print-directory run VALGRIND=$(VALGRIND)
	@$(OBJ)testclient --port=$(PORT) --private-key=keys/private.key --client-cert=client-cert/cert.pem --client-key=client-cert/key.pem --ca-file=$(CA_FILE) $(DEBUG)
ifeq ($(VALGRIND),1)
	@$(MAKE) --no-print-directory kill
	@echo valgrind log in $(VALGRIND_LOG)
endif

# ABOVE: when running the test suite with valgrind we need the
# keyserver to terminate; hence the extra $(MAKE) kill at the end

$(OBJ):
	@mkdir -p $@

$(OBJ)kssl_server: $(SERVER_OBJS) ; @$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@
$(OBJ)kssl_testclient: $(TEST_OBJS) ; @$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@

$(OBJ)%.o: %.c ; @$(COMPILE.c) $(CFLAGS) $(OUTPUT_OPTION) $<

$(OBJ)kssl_server.o: kssl.h
$(OBJ)kssl_testclient.o: kssl.h
