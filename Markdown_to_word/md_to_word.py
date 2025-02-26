from spire.doc import *
from spire.doc.common import *
from pathlib import Path

# Create a Document object
document = Document()

# Load a Markdown file
document.LoadFromFile(r"C:\Users\HunterL\Downloads\02-13_Meeting_Policy_Management_SBOM_Features_and_Workflow_Use_Cases.md")

# Save it as a docx file
document.SaveToFile("output/ToWord.docx", FileFormat.Docx2016)

# Dispose resources
document.Dispose()