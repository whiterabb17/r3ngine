import logging
from apme.llm_orchestrator import LLMPathOrchestrator

logger = logging.getLogger(__name__)

def run_llm_apme(self, scan_history_id):
    """On-demand Celery task for LLM-assisted Attack Path Modeling.

    Args:
        self (RengineTask): Celery task instance bound to the task context.
        scan_history_id (int): The ID of the ScanHistory to run attack path modeling on.

    Returns:
        dict: A dictionary containing task status and the number of paths generated.
    """
    logger.info("Task run_llm_apme started for scan_history_id=%s", scan_history_id)
    # Initialize the LLM attack path orchestrator
    orchestrator = LLMPathOrchestrator()
    # Run the orchestrator on the scan history ID
    result = orchestrator.run(scan_history_id)
    
    if "error" in result:
        logger.error("run_llm_apme failed: %s", result['error'])
        return {"status": "failed", "error": result["error"]}
        
    logger.info("run_llm_apme completed successfully. Paths found: %s", result.get('total_paths', 0))
    return {"status": "success", "total_paths": result.get("total_paths", 0)}
