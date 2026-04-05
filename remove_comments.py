"""Script to remove all # comments from Python source files."""

import tokenize
import io
import os
import glob


def remove_comments(source: str) -> str:
    result = []
    prev_end = (1, 0)
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except tokenize.TokenError:
        return source  # return unchanged if tokenization fails

    for tok_type, tok_string, tok_start, tok_end, tok_line in tokens:
        if tok_type == tokenize.COMMENT:
            # Skip comment token, but preserve the newline that follows
            continue
        if tok_type == tokenize.ENDMARKER:
            break

        # Fill gap from previous token end to current token start
        start_row, start_col = tok_start
        end_row, end_col = prev_end

        if start_row == end_row:
            # Same line: add spaces to fill the gap
            gap = start_col - end_col
            if gap > 0:
                result.append(" " * gap)
        else:
            # Different lines: add newlines and indentation
            result.append("\n" * (start_row - end_row))
            result.append(" " * start_col)

        result.append(tok_string)
        prev_end = tok_end

    return "".join(result)


def process_file(filepath: str) -> None:
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        source = f.read()

    cleaned = remove_comments(source)

    if cleaned != source:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(cleaned)
        print(f"Cleaned: {filepath}")
    else:
        print(f"No changes: {filepath}")


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    # Process only wp_hijack/ source files (not build/ or .venv/)
    pattern = os.path.join(base_dir, "wp_hijack", "**", "*.py")
    py_files = glob.glob(pattern, recursive=True)
    # Also include top-level wp_hijack files
    top_files = glob.glob(os.path.join(base_dir, "wp_hijack", "*.py"))
    all_files = sorted(set(py_files + top_files))

    print(f"Processing {len(all_files)} Python files...\n")
    for fp in all_files:
        process_file(fp)
    print("\nDone.")


if __name__ == "__main__":
    main()
