# What is *DUdetector*?

**DUdetector** is a dual-granularity unsupervised framework for network anomaly detection. It integrates an Enhanced Transformer and a Conv1d-and-MaxPool1d AutoEncoder with residual connections (**CM&RC-AE**) to enable both coarse-grained segment-level detection and fine-grained point-level detection.

## PCAP_Vectorization

*PCAP_Vectorization* is a PCAP traffic vectorization method proposed in this work. By introducing two-dimensional jitter correlation statistics in the **Channel**, it characterizes abnormal communication rhythms based on the joint variation between source and destination hosts, thereby expanding the feature dimensionality of traffic vectors and enhancing their ability to represent complex interaction behaviors.

To perform PCAP vectorization, run:

```bash
python Pcap2TSV_main.py
```


## Citation

If you use this repository in your research, please cite our paper:

```bibtex
@article{geng2025dudetector,
  title={DUdetector: A dual-granularity unsupervised model for network anomaly detection},
  author={Geng, Haijun and Ma, Qi and Chi, Haotian and Zhang, Zhi and Yang, Jing and Yin, Xia},
  journal={Computer Networks},
  volume={257},
  pages={110937},
  year={2025},
  publisher={Elsevier}
}
```
