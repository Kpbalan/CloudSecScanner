# Copyright (c) 2025 Krishna Prasad Balan
#
# This file is licensed under the MIT License. See the LICENSE file for details.


import csv

from datetime import datetime
from fpdf import FPDF

misconfig_summary_text = ("The purpose of this scan is to generate a report of all potential misconfigurations "
                          "identified across the cloud components in the selected GCP project. This section provides a "
                          "comprehensive list of all misconfigurations identified during the scan, their criticality and "
                          "actionable measures needed to remediate them.")
misconfig_summary_chart_text =("The chart here summarizes the count of identified potential vulnerabilities categorized "
                               "based on their severity or the impact they could have on the security of the environment"
                               " if they are not remediated. The criticality of the misconfiguration is also determined "
                               "by the negative impact the misconfiguration would potentially create on the environment "
                               "if any malicious hacker exploits the vulnerability exposed by the misconfiguration. "
                               "This pie chart here represents the percentage distribution of misconfigurations "
                               "according to their criticality.")
misconfig_scan_trend_text = ("This trend graph here shows the progress of the security posture of the scanned GCP project "
                             "over a period of time. The x-axis shows the dates when the scans were executed whereas the "
                             "y-axis shows the count of misconfigurations identified after every scan. Each colored "
                             "line represents a criticality level.")

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

def scan_file_pdf_converter(report_file, pdf_report, chart_images, scan_time, project):
    summary_data = read_summary_as_table(report_file)
    current_datetime = datetime.now().strftime("%A, %B %d, %Y")
    current_time = datetime.now().time().strftime("%H:%M:%S")
    scanned_date_time = str(current_datetime) + "  " + str(current_time)

    pdf = PDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    #Title : Misconfigurations Report
    pdf.set_font("Arial", style="B", size=14)
    pdf.set_text_color(0, 0, 128)
    pdf.cell(0, 10, "Misconfigurations Report", border=0, ln=1, align="L")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(3)  # Line break
    pdf.set_font("Arial", style="B", size=10)
    pdf.cell(0, 8, "Scan Date/Time: ", border=0, ln=0, align="L")
    pdf.set_x(pdf.l_margin + 50)
    pdf.set_font("Arial",style="", size=10)
    pdf.cell(100, 8, scanned_date_time, border=0, ln=1)
    # pdf.ln(1)
    pdf.set_font("Arial", style="B", size=10)
    pdf.cell(0, 7, "Scan Duration: ", border=0, ln=0, align="L")
    pdf.set_x(pdf.l_margin + 50)
    pdf.set_font("Arial", style="", size=10)
    pdf.cell(100, 7, str(round(scan_time, 2)) + " seconds", border=0, ln=1)
    # pdf.ln(1)
    pdf.set_font("Arial", style="B", size=10)
    pdf.cell(0, 7, "Scanned GCP Project name: ", border=0, ln=0, align="L")
    pdf.set_x(pdf.l_margin + 50)
    pdf.set_font("Arial", style="I", size=10)
    pdf.cell(100, 7, project, border=0, ln=1)
    pdf.ln(3)
    pdf.set_font("Arial", size=9)
    pdf.multi_cell(0, 5, misconfig_summary_text, border=0, align="L")
    pdf.ln(3)  # Line break
    pdf.set_font("Arial", style="B", size=10)


    pdf.set_fill_color(200, 220, 255)  # Light blue background for header
    pdf.cell(15, 10, "Severity", border=1, align="C", fill=True)
    pdf.cell(95, 10, "Misconfiguration", border=1, align="C", fill=True)
    page_width = pdf.w  # Total page width
    current_x = pdf.get_x()  # Current x position
    remaining_width = page_width - current_x - pdf.r_margin  # Remaining width
    pdf.cell(remaining_width, 10, "Recommendation", border=1, align="C", fill=True)
    pdf.set_font("Arial",style="")

    pdf.ln()
    pdf.set_fill_color(240, 240, 240)
    column_widths = [15, 95, 80]
    for row in summary_data:
        max_height = 0

        for i, cell in enumerate(row):
            if i < len(row) - 2:
                height_used = 10
                pdf.set_font("Arial", size=8)
                if "Critical" in cell:
                    pdf.set_text_color(255, 0, 0)
                pdf.cell(15, height_used, cell, border=1, align="C", fill=False)
                pdf.set_text_color(0, 0, 0)
            elif i < len(row) - 1:
                pdf.set_font("Arial", size=6)
                height_used = pdf.cell_with_wrapped_text(95, 10, cell,border=1)
            else:
                page_width = pdf.w  # Total page width
                current_x = pdf.get_x()  # Current x position
                remaining_width = page_width - current_x - pdf.r_margin  # Remaining width
                pdf.set_font("Arial", size=6)
                height_used = pdf.cell_with_wrapped_text(remaining_width, max_height, cell, border=1)
            max_height = max(max_height, height_used)
        pdf.ln(max_height)

    for image_path in chart_images:
        pdf.add_page()
        if image_path == "criticality_chart.png":
            # Title : Misconfigurations Summary
            pdf.set_font("Arial", style="B", size=12)
            pdf.cell(0, 10, "Misconfiguration Summary", border=0, ln=1, align="L")
            pdf.ln(4)
            pdf.set_font("Arial", size=9)
            pdf.multi_cell(0, 5, misconfig_summary_chart_text, border=0, align="L")
            pdf.ln(3)
            # Line break
        else:
            # Title : Misconfigurations Summary
            pdf.set_font("Arial", style="B", size=12)
            pdf.cell(0, 10, "Cloud Scan Trend", border=0, ln=1, align="L")
            pdf.ln(5)  # Line break
            pdf.set_font("Arial", size=9)
            pdf.multi_cell(0, 5, misconfig_scan_trend_text, border=0, align="L")
            pdf.ln(3)
        pdf.image(image_path, x=10, y=55, w=190)


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