import os
import logging
import subprocess

logger = logging.getLogger(__name__)


def get_template_counts_for_tags(tags: list, template_dirs: list) -> dict:
    """Fast python-based tag counting to avoid Nuclei OOM and timeouts.
    
    Reads the 'tags:' line from all .yaml templates and tallies counts 
    for the requested tags. This takes ~10 seconds for 100k+ templates
    but prevents `nuclei -tl` from exhausting memory.
    """
    if not tags or not template_dirs:
        return {}
        
    requested_tags = set(tags)
    tag_counts = {tag: 0 for tag in requested_tags}
    
    for d in template_dirs:
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            for file in files:
                if file.endswith('.yaml'):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            for line in f:
                                line = line.strip()
                                if line.startswith('tags:'):
                                    tags_str = line.split(':', 1)[1].strip()
                                    file_tags = [t.strip().strip("'").strip('"') for t in tags_str.split(',')]
                                    for t in file_tags:
                                        if t in requested_tags:
                                            tag_counts[t] += 1
                                    break  # Only parse the first tags line in info block
                    except Exception:
                        pass
    return tag_counts

def count_templates_for_tag(tag: str, template_dirs: list) -> int:
    """Count nuclei templates matching a given tag by running ``nuclei -tl``.

    Returns 0 on any error so callers treat unknown/unavailable tags as zero-cost.
    """
    if not tag or not template_dirs:
        return 0
    cmd = ['nuclei', '-tl']
    for d in template_dirs:
        cmd += ['-t', d]
    cmd += ['-tags', tag]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        return len(lines)
    except Exception as exc:
        logger.warning('count_templates_for_tag failed for tag %s: %s', tag, exc)
        return 0


def build_tag_batches(tags: list, tag_counts: dict, max_per_batch: int = 100, max_tags: int = 3) -> list:
    """Group tags into batches bounded by template count AND tag count.

    Uses a greedy first-fit algorithm over the supplied tag order. A batch is
    closed when EITHER cumulative template count would exceed max_per_batch OR
    the batch already holds max_tags tags.

    The max_tags ceiling is critical: when count_templates_for_tag returns 0 for
    every tag (e.g. during a first scan before templates are cached), the template-
    count guard never fires and without max_tags all tags collapse into one batch,
    causing nuclei to receive all tags at once and crash.

    A tag whose individual template count already exceeds max_per_batch is placed
    alone in its own batch — further splitting at the file level is not done here.

    This function is pure (no I/O, no randomness) and safe to call from a
    Temporal workflow.

    Args:
        tags: Ordered list of tag strings to batch.
        tag_counts: Mapping of tag -> template count (missing tags treated as 0).
        max_per_batch: Maximum cumulative template count allowed per batch.
        max_tags: Maximum number of tags allowed per batch regardless of count.

    Returns:
        List of batches; each batch is a list of tag strings. Empty when tags=[].
    """
    if not tags:
        return []

    batches: list = []
    current_batch: list = []
    current_count: int = 0

    for tag in tags:
        count = tag_counts.get(tag, 0)
        over_template_limit = current_batch and current_count + count > max_per_batch
        over_tag_limit = len(current_batch) >= max_tags
        if over_template_limit or over_tag_limit:
            batches.append(current_batch)
            current_batch = [tag]
            current_count = count
        else:
            current_batch.append(tag)
            current_count += count

    if current_batch:
        batches.append(current_batch)

    return batches
