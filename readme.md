# KubeGuard MCP Server

A Model Context Protocol (MCP) server for Kubernetes Role security analysis using LLM-assisted prompt chaining, based on the KubeGuard research paper: "LLM-Assisted Kubernetes Hardening via Configuration Files and Runtime Logs Analysis."

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## TestRun:
MCP server :
$_python -m kubeguard.main_

Standalone Test:
$python .\examples\fastmcp_demo.py

## Citation

If you use KubeGuard in your research, please cite the original paper:

```bibtex
@article{kubeguard2025,
  title={KubeGuard: LLM-Assisted Kubernetes Hardening via Configuration Files and Runtime Logs Analysis},
  journal={arXiv preprint arXiv:2509.04191},
  year={2025}
}
```
