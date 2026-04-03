use std::process::Command;

fn main() {
	// Capture build timestamp in UTC for display in config summary
	let output = Command::new("date").arg("-u").arg("+%Y-%m-%d %H:%M UTC")
		.output()
		.expect("failed to run date");
	let timestamp = String::from_utf8(output.stdout)
		.expect("invalid UTF-8 from date")
		.trim()
		.to_string();
	println!("cargo:rustc-env=BUILD_TIMESTAMP={}", timestamp);
}
