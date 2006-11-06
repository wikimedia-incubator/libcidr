# Big definition of tests to run

our %TESTS = (
	'mkstr' => {
		# Wacky v4 address format
		'127.0347.0xfe8/0xff.0340.0' => [
			{ 'res' => '127.231.15.232/11', },
			{ 'args' => '-m', 'res' => '127.231.15.232/255.224.0.0', },
		],
	},
);
