#include "../../event_class/event_class.h"
#include "../../flags/flags_definitions.h"
#include "../../helpers/proc_parsing.h"

#if defined(__NR_prctl) && defined(__NR_clone3) && defined(__NR_wait4)

#include <linux/sched.h>

TEST(SyscallExit, prctlX)
{
	auto evt_test = get_syscall_event_test(__NR_prctl, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	const char newname[] = "changedname";
	int option = 15; //PR_SET_NAME
	unsigned long arg3 = 0;
	unsigned long arg4 = 0;
	unsigned long arg5 = 0;

	/* We need to use `SIGCHLD` otherwise the parent won't receive any signal
	 * when the child terminates.
	 */
	struct clone_args cl_args = {0};
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));
	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);

	if (ret_pid == 0)
	{
		/*
		 * Call the `prctl`
		 */
		int res = syscall(__NR_prctl, option, newname, arg3, arg4, arg5);
		assert_syscall_state(SYSCALL_SUCCESS, "prctl", res,EQUAL,0);
		exit(EXIT_SUCCESS);

	}

	/* Catch the child before doing anything else. */
	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL, -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "The prctl call is successful while it should fail..." << std::endl;
	}


	evt_test->disable_capture();

	evt_test->assert_event_presence(ret_pid);

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/


	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (uint64_t)0);

	/* Parameter 2: option (type: PT_ENUMFLAGS32) */
	evt_test->assert_numeric_param(2, option); //PR_SET_NAME

	/* Parameter 3: arg2 (type: PT_CHARBUFARRAY) */
	//evt_test->assert_charbuf_param(3, newname);

	/* Parameter 4: arg3 (type: PT_UINT64) */
	evt_test->assert_numeric_param(4, arg3);

	/* Parameter 5: arg4 (type: PT_UINT64) */
	evt_test->assert_numeric_param(5, arg4);

	/* Parameter 6: arg5 (type: PT_UINT64) */
	evt_test->assert_numeric_param(6, arg5);

	/* Parameter 6: arg2str (type: PT_UINT64) */
	evt_test->assert_charbuf_param(7, newname);

	/* Parameter 7: arg2int (type: PT_UINT64) */
	evt_test->assert_numeric_param(8, (uint64_t)0);


	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(8);

}
#endif