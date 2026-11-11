from pathlib import Path

def read_log(file_path):
    # Convert the received path into a Path object.
    path = Path(file_path)
    lines = []

    # Check if the path points to a valid file.
    if not path.is_file():
        print("Invalid file path")
        return []

    try:
        # Open the file in read mode. The with statement
        # automatically closes it after execution.
        with path.open("r") as file:

            # Iterate through the file and store each
            # line in the list without surrounding whitespace.
            for line in file:
                lines.append(line.strip())

        # Return all collected lines.
        return lines

    except OSError as error:
        # Handle operating system errors during file access.
        print(f"Error reading file: {error}")
        return []