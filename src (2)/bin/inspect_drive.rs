use recover_droid::device::Device;
use recover_droid::filesystem::detect_filesystem;

fn main() {
    let dev_path = "/dev/sda";
    println!("Opening device '{}'...", dev_path);
    let device = match Device::open(dev_path) {
        Ok(dev) => dev,
        Err(e) => {
            println!("Error opening device: {}", e);
            return;
        }
    };

    println!("Detecting filesystem...");
    let parser = match detect_filesystem(&device) {
        Ok(p) => p,
        Err(e) => {
            println!("Error detecting filesystem: {}", e);
            return;
        }
    };

    let info = parser.get_info();
    println!("Filesystem info: {:?}", info);

    println!("Scanning deleted files...");
    let deleted = match parser.scan_deleted(&device) {
        Ok(d) => d,
        Err(e) => {
            println!("Error scanning deleted files: {}", e);
            return;
        }
    };

    println!("Found {} deleted files:", deleted.len());
    for (i, df) in deleted.iter().enumerate() {
        let offset = parser.get_file_offset(df);
        println!(
            "[{}] Name: {}, Size: {}, Start Cluster: {}, Offset: {:?}",
            i + 1,
            df.name,
            df.size,
            df.start_cluster,
            offset
        );
    }
}
