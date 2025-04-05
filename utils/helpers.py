# Copyright (c) 2025 Krishna Prasad Balan
#
# This file is licensed under the MIT License. See the LICENSE file for details.

import csv
from datetime import datetime
from fpdf import FPDF

class PDF(FPDF):
    def cell_with_wrapped_text(self, width, height, text, border=1, align="L"):
        # Add wrapped text using multi_cell
        x, y = self.get_x(), self.get_y()  # Save current position
        self.multi_cell(width, height, text, border=0, align=align)
        wrapped_height = self.get_y() - y
        if border:
            self.rect(x, y, width, wrapped_height)
        self.set_xy(x + width, y)
        return wrapped_height
# def display_yaml_table(yaml_file):
#     """
#     Displays the contents of a YAML file in a table format.
#
#     Args:
#         yaml_file (str): Path to the YAML file.
#     """
#     try:
#         with open(yaml_file, 'r') as file:
#             data = yaml.safe_load(file)
#     except FileNotFoundError:
#         print(f"Error: File not found: {yaml_file}")
#         return
#     except yaml.YAMLError as e:
#         print(f"Error parsing YAML file: {e}")
#         return
#
#     if not data:
#         print("YAML file is empty or contains no data.")
#         return
#
#     if isinstance(data, list):
#         headers = data[0].keys()
#         rows = [row.values() for row in data]
#     elif isinstance(data, dict):
#         headers = data.keys()
#         rows = [data.values()]
#     else:
#         print("Unsupported YAML format. Data should be a list of dictionaries or a dictionary.")
#         return
#
#     print(tabulate(rows, headers=headers, tablefmt="grid"))

def display_value(value):
    if value:
        print("\033[31mTrue\033[0m")# Red color for True
    else:
        print("\033[32mFalse\033[0m")

# Function to conditionally color values
def color_value(key, value):
    if isinstance(value, bool):
        if str(key) == 'public_access_enabled' and value == True:
            return "\033[1;31m" +str(value) + "\033[0m"
        elif str(key) == 'has_overly_permissive_role_bindings' and value == True:
            return "\033[1;31m" +str(value) + "\033[0m"
        else:
            return "\033[32m" +str(value) + "\033[0m"
    return value
# Read the text file and format it into rows and columns
def read_summary_as_table(txt_file):
    with open(txt_file, "r") as file:
        lines = file.readlines()
        table_data = [line.strip().split("|") for line in lines]  # Split lines by commas
    return table_data

def add_subheader(self, text):
    self.set_font("Arial", style="B", size=12)
    self.cell(0, 10, text, border=0, ln=1, align="L")
    self.ln(5)  # Line break

def scan_file_pdf_converter(report_file, pdf_report, chart_images):
    summary_data = read_summary_as_table(report_file)

    pdf = PDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    #Title : Misconfigurations Report
    pdf.set_font("Arial", style="B", size=12)
    pdf.cell(0, 10, "Misconfigurations Report", border=0, ln=1, align="L")
    pdf.ln(5)  # Line break

    pdf.set_font("Arial", size=10)


    pdf.set_fill_color(200, 220, 255)  # Light blue background for header
    pdf.cell(15, 10, "Severity", border=1, align="C", fill=True)
    pdf.cell(90, 10, "Misconfiguration", border=1, align="C", fill=True)
    page_width = pdf.w  # Total page width
    current_x = pdf.get_x()  # Current x position
    remaining_width = page_width - current_x - pdf.r_margin  # Remaining width
    pdf.cell(remaining_width, 10, "Recommendation", border=1, align="C", fill=True)

    pdf.ln()
    pdf.set_fill_color(240, 240, 240)
    column_widths = [15, 90, 85]
    for row in summary_data:
        max_height = 0
        # row_heights = []
        # for i, text in enumerate(row):
        #     if i == 0:  # If it's not the first cell, calculate wrapped height
        #         row_heights.append(10)
        #     else:
        #         x, y = pdf.get_x(), pdf.get_y()
        #         pdf.multi_cell(column_widths[i], 10, text, border=0)
        #         wrapped_height = pdf.get_y() - y
        #         pdf.set_xy(x, y)  # Reset position for later actual drawing
        #         row_heights.append(wrapped_height)

        #max_height = max(row_heights)

        for i, cell in enumerate(row):
            if i < len(row) - 2:
                height_used = 10
                pdf.set_font("Arial", size=8)
                pdf.cell(15, height_used, cell, border=1, align="C", fill=False)
            elif i < len(row) - 1:
                pdf.set_font("Arial", size=7)
                #pdf.cell(85, 10, cell, border=1, align="L", fill=False)
                height_used = pdf.cell_with_wrapped_text(90, 10, cell,border=1)
                #max_height = max(max_height, height_used)
            else:
                page_width = pdf.w  # Total page width
                current_x = pdf.get_x()  # Current x position
                remaining_width = page_width - current_x - pdf.r_margin  # Remaining width
                pdf.set_font("Arial", size=6)
                #pdf.cell(remaining_width, 10, cell, border=1, ln=True)
                height_used = pdf.cell_with_wrapped_text(remaining_width, max_height, cell, border=1)
                #max_height = max(max_height, height_used)
            max_height = max(max_height, height_used)
        pdf.ln(max_height)

    for image_path in chart_images:
        pdf.add_page()
        if image_path == "criticality_chart.png":
            # Title : Misconfigurations Summary
            pdf.set_font("Arial", style="B", size=12)
            pdf.cell(0, 10, "Misconfiguration Summary", border=0, ln=1, align="L")
            pdf.ln(5)  # Line break
        else:
            # Title : Misconfigurations Summary
            pdf.set_font("Arial", style="B", size=12)
            pdf.cell(0, 10, "Cloud Scan Trend", border=0, ln=1, align="L")
            pdf.ln(5)  # Line break
            pdf.multi_cell(0, 10, " \n Cloud Scan Trend  \n")
        pdf.image(image_path, x=10, y=10, w=190)  # Adjust dimensions as needed


    # Save the PDF report file
    pdf.output(pdf_report)
    print(f"PDF successfully created: {pdf_report}")

# Function to log warnings and counts
def capture_misconfigs_trend_to_csv(counts, file_path):
    # Get the current timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Prepare the data to log
    row = [timestamp] + list(counts.values())  # Add timestamp to counts

    # Check if the file exists
    try:
        with open(file_path, 'x', newline='') as file:
            # Create a new CSV with headers if it doesn't exist
            writer = csv.writer(file)
            writer.writerow(["Timestamp", "Low", "Medium", "High", "Critical"])
            writer.writerow(row)
    except FileExistsError:
        with open(file_path, 'a', newline='') as file:
            # Append to the existing CSV
            writer = csv.writer(file)
            writer.writerow(row)