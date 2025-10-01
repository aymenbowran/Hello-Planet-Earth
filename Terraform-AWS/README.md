# 🏗️ Terraform Infrastructure as Code (IaC) 💾

This repository contains my personal and experimental **Terraform** configurations for provisioning and managing infrastructure on various cloud providers (primarily AWS/Azure/GCP). IaC ensures that infrastructure is **version-controlled**, **auditable**, and **reproducible**.

---

## 🌍 Modules and Examples

* **Basic VPC/Networking:** A foundational setup for creating a secure and structured virtual private cloud environment.
* **Compute Instances:** Examples of provisioning VMs/EC2 instances, including user data for initial setup.
* **State Management:** Demonstrations of using remote backends (e.g., S3/Azure Blob Storage) to securely manage the Terraform state file.
* **Reusable Modules:** Simple, self-contained modules to provision common resources (e.g., a security group or an S3 bucket).

---

## 🔑 Key IaC Skills Demonstrated

| Concept | Description |
| :--- | :--- |
| **Resource Provisioning** | Defining cloud resources in HCL and managing their lifecycle (`plan`, `apply`, `destroy`). |
| **Modularity** | Breaking down complex infrastructure into smaller, reusable components. |
| **Variables & Outputs** | Parameterizing configurations for flexibility and securely sharing resulting data. |
| **Backend Configuration** | Ensuring team-friendly and secure state locking/storage. |
| **Idempotency** | The core principle of IaC: running the same configuration multiple times yields the same result. |

---

## 📖 What to Focus On

As a beginner, pay close attention to the **variables** and **outputs** files, as they control how the configuration is customized and how information is passed between resources. For experienced users, note the file structure and module design choices.

---

_Explore the folders to see how I define and manage infrastructure with code!_