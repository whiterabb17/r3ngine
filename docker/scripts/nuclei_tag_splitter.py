import os
import re
import json
from collections import defaultdict

# Regex to safely replace a tag in a comma-separated list without breaking other tags
# e.g., \b(tag)\b
# But wait, YAML can have spaces, quotes, etc.

def get_yaml_files(base_dir):
    yaml_files = []
    for root, _, files in os.walk(base_dir):
        for file in files:
            if file.endswith(('.yaml', '.yml')):
                yaml_files.append(os.path.join(root, file))
    return yaml_files

def parse_tags_from_text(content):
    """
    Extracts tags from a YAML content string.
    Only handles comma-separated tags on the same line as `tags:`, 
    which is standard for Nuclei templates.
    """
    match = re.search(r'^[\s-]*tags:\s*([^\r\n]+)', content, re.MULTILINE)
    if not match:
        return []
    
    tag_str = match.group(1)
    # Remove array syntax if it's like `tags: ["cve", "xss"]`
    if tag_str.startswith('[') and tag_str.endswith(']'):
        tag_str = tag_str[1:-1]
    
    tags = [t.strip().strip("'\"") for t in tag_str.split(',')]
    return [t for t in tags if t]

def replace_tag_in_text(content, old_tag, new_tag):
    """
    Replaces a specific tag in the `tags:` line safely.
    """
    def replacer(match):
        prefix = match.group(1)
        tag_str = match.group(2)
        
        # Split by comma, preserving original whitespace if possible
        # For simplicity, we can just rebuild the string
        # but to be extremely safe, we replace only the exact whole word
        # within the tag_str.
        
        # We need a regex that finds the exact word bordered by commas/quotes/spaces/brackets
        # old_tag is the exact string.
        # e.g. "cve, cve2020, xss" -> replace "cve" but not "cve2020"
        
        # A sub-regex to replace old_tag with new_tag in tag_str
        pattern = r'(?<![\w\-])' + re.escape(old_tag) + r'(?![\w\-])'
        new_tag_str = re.sub(pattern, new_tag, tag_str)
        
        return f"{prefix}{new_tag_str}"

    return re.sub(r'(^[\s-]*tags:\s*)([^\r\n]+)', replacer, content, flags=re.MULTILINE)

def main():
    templates_dir = os.getenv("NUCLEI_TEMPLATES_DIR", "/root/nuclei-templates")
    max_templates = int(os.getenv("NUCLEI_MAX_TEMPLATES_PER_BATCH", "60"))
    manifest_path = os.getenv("NUCLEI_SPLIT_TAGS_MANIFEST", "/root/nuclei-templates/split_tags.json")

    print(f"Scanning templates in {templates_dir}...")
    yaml_files = get_yaml_files(templates_dir)
    print(f"Found {len(yaml_files)} YAML files.")

    # Pass 1: Build mapping of tag -> list of files
    tag_to_files = defaultdict(list)
    
    for file in yaml_files:
        try:
            with open(file, 'r', encoding='utf-8') as f:
                content = f.read()
            tags = parse_tags_from_text(content)
            for tag in tags:
                tag_to_files[tag].append(file)
        except Exception as e:
            # Skip unreadable files
            pass

    print(f"Discovered {len(tag_to_files)} unique tags.")

    manifest = {}
    files_modified = 0

    leeway = int(os.getenv("NUCLEI_SPLIT_LEEWAY", "15"))

    # Pass 2: Identify oversized tags and rewrite
    for tag, files in tag_to_files.items():
        if len(files) > (max_templates + leeway):
            print(f"Tag '{tag}' has {len(files)} templates. Splitting into batches of {max_templates}...")
            
            manifest[tag] = []
            
            # Chunk files
            chunks = [files[i:i + max_templates] for i in range(0, len(files), max_templates)]
            for chunk_idx, chunk_files in enumerate(chunks):
                new_tag = f"{tag}_{chunk_idx + 1}"
                manifest[tag].append(new_tag)
                
                for file in chunk_files:
                    try:
                        with open(file, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        new_content = replace_tag_in_text(content, tag, new_tag)
                        
                        if new_content != content:
                            with open(file, 'w', encoding='utf-8') as f:
                                f.write(new_content)
                            files_modified += 1
                    except Exception as e:
                        print(f"Error modifying {file}: {e}")

    # Write manifest
    if manifest:
        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=4)
        print(f"Manifest written to {manifest_path} with {len(manifest)} split tags.")
    else:
        print("No oversized tags found. Manifest not required.")
        # Create an empty manifest so the backend doesn't fail reading it
        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump({}, f)

    print(f"Finished splitting tags. Modified {files_modified} file injections.")

if __name__ == "__main__":
    main()
