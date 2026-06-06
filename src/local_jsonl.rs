use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader};
use std::path::Path;

pub(crate) fn open_append_private(path: &Path) -> Result<File, std::io::Error> {
    create_parent_dir(path)?;

    let mut options = OpenOptions::new();
    options.append(true).create(true);
    apply_private_mode(&mut options);

    options.open(path)
}

pub(crate) fn create_new_private(path: &Path) -> Result<File, std::io::Error> {
    create_parent_dir(path)?;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    apply_private_mode(&mut options);

    options.open(path)
}

pub(crate) fn create_truncate_private(path: &Path) -> Result<File, std::io::Error> {
    create_parent_dir(path)?;

    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    apply_private_mode(&mut options);

    options.open(path)
}

pub(crate) fn for_each_nonempty_line<E>(
    path: &Path,
    mut handle_line: impl FnMut(usize, &str) -> Result<(), E>,
) -> Result<(), E>
where
    E: From<std::io::Error>,
{
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        handle_line(index.saturating_add(1), &line)?;
    }

    Ok(())
}

fn create_parent_dir(path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    Ok(())
}

fn apply_private_mode(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
}
