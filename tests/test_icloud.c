#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <cmocka.h>
#include <icloud.h>

struct test_state {
	char* username;
	char* password;
};

/* A test case that does nothing and succeeds. */
static void test_auth_credentials(void **state) {
    struct test_state* test_state = *state;

	struct icloud* icloud = icloud_new(test_state->username, test_state->password, text_file_cache());
	assert_true(icloud != NULL);
	if (icloud_needs_2fa(icloud)) {
		char code[7];
		printf("Enter 2FA code: ");
		fgets(code, 7, stdin);
		icloud_2fa(icloud, code);
	}
	//assert_false(icloud_needs_2fa(icloud));
	icloud_free(icloud);
}

static int setup(void** state) {
	*state = malloc(sizeof(struct test_state));
	struct test_state* test_state = *state;

	assert_true(getenv("TEST_ICLOUD_USERNAME") != NULL);
	assert_true(getenv("TEST_ICLOUD_PASSWORD") != NULL);
	test_state->username = getenv("TEST_ICLOUD_USERNAME");
	test_state->password = getenv("TEST_ICLOUD_PASSWORD");
	return 0;
}

static int teardown(void** state) {
	if (*state != NULL) {
		free(*state);
	}
	return 0;	
}

int main(int argc, char* argv[]) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_auth_credentials),
    };

    return cmocka_run_group_tests(tests, setup, teardown);
}

