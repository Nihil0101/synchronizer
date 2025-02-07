import os
import shutil
import time
import logging
import hashlib
import sys


def compute_file_hash(file_path, algorithm="sha256"):
    """Compute the hash of a file."""
    hash_func = hashlib.new(algorithm)
    with open(file_path, "rb") as file:
        while chunk := file.read(8192):
            hash_func.update(chunk)
    return hash_func.hexdigest()


def ensure_directory_exists(directory_path, logger):
    """Ensure that a directory exists; create if not."""
    if not os.path.exists(directory_path):
        try:
            os.makedirs(directory_path)
            logger.info(f"Created directory: {directory_path}")
        except Exception as e:
            logger.error(f"Failed to create directory {directory_path}: {e}")
            return False
    return True


def copy_file(source_file, replica_file, logger):
    """Copy a file from source to replica."""
    try:
        shutil.copy2(source_file, replica_file)
        logger.info(f"Copied file: {source_file} to {replica_file}")
    except Exception as e:
        logger.error(f"Failed to copy file {source_file} to {replica_file}: {e}")


def sync_files(source_path, replica_path, logger):
    """Ensure files in the source are copied to replica."""
    for root, _, files in os.walk(source_path):
        relative_root = os.path.relpath(root, source_path)
        replica_root = os.path.join(replica_path, relative_root)

        ensure_directory_exists(replica_root, logger)

        for file_name in files:
            source_file = os.path.join(root, file_name)
            replica_file = os.path.join(replica_root, file_name)

            if os.path.exists(replica_file):
                if compute_file_hash(source_file) != compute_file_hash(replica_file):
                    copy_file(source_file, replica_file, logger)
            else:
                copy_file(source_file, replica_file, logger)


def cleanup_replica(source_path, replica_path, logger):
    """Remove extra files and directories from replica that are not in source."""
    for root, dirs, files in os.walk(replica_path, topdown=False):
        relative_root = os.path.relpath(root, replica_path)
        source_root = os.path.join(source_path, relative_root)

        for file_name in files:
            replica_file = os.path.join(root, file_name)
            source_file = os.path.join(source_root, file_name)
            if not os.path.exists(source_file):
                try:
                    os.remove(replica_file)
                    logger.info(f"Deleted file: {replica_file}")
                except Exception as e:
                    logger.error(f"Failed to delete file {replica_file}: {e}")

        for dir_name in dirs:
            replica_dir = os.path.join(root, dir_name)
            source_dir = os.path.join(source_root, dir_name)
            if not os.path.exists(source_dir):
                try:
                    shutil.rmtree(replica_dir)
                    logger.info(f"Removed directory: {replica_dir}")
                except Exception as e:
                    logger.error(f"Failed to remove directory {replica_dir}: {e}")


def synchronize(source_path, replica_path, log_file, interval):
    """Main function to synchronize source and replica at intervals."""
    logging.basicConfig(
        filename=log_file,
        format="%(asctime)s %(message)s",
        filemode="w",
        level=logging.INFO,
    )
    logger = logging.getLogger()
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    while True:
        if not ensure_directory_exists(
            source_path, logger
        ) or not ensure_directory_exists(replica_path, logger):
            logger.error("Source or replica directory does not exist.")
            return

        sync_files(source_path, replica_path, logger)
        cleanup_replica(source_path, replica_path, logger)

        time.sleep(interval)


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print(
            "Usage: python sync.py <source_folder> <replica_folder> <log_file> <sync_interval>"
        )
        sys.exit(1)

    source_folder = sys.argv[1]
    replica_folder = sys.argv[2]
    log_file = sys.argv[3]
    sync_interval = int(sys.argv[4])

    synchronize(source_folder, replica_folder, log_file, sync_interval)
