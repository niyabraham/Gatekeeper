"""
extractor.py — Lossless data extraction from Excel files.

Uses openpyxl only. openpyxl parses the XML/zip structure of the workbook
directly — it never loads the VBA engine and never executes a macro, even
on an .xlsm file. That's what makes reading "safe" regardless of what a
macro inside the file might do if opened in real Excel.

Note: a plain `pandas.read_excel()` on a merged-cell sheet returns the
value only in the merged range's top-left cell and None/NaN everywhere
else in that range — that IS data loss for a survey/questionnaire sheet
with merged header cells. This module fills every cell in a merged range
with its value before writing output, so nothing merged looks "missing".
"""

import openpyxl
from openpyxl.utils import range_boundaries


def _merged_fill_map(sheet):
    """Map every (row, col) inside a merged range to that range's value."""
    fill = {}
    for merged_range in sheet.merged_cells.ranges:
        min_col, min_row, max_col, max_row = range_boundaries(str(merged_range))
        top_left_value = sheet.cell(row=min_row, column=min_col).value
        for row in range(min_row, max_row + 1):
            for col in range(min_col, max_col + 1):
                fill[(row, col)] = top_left_value
    return fill


def extract_all_data(file_path, output_path):
    """
    Read every worksheet/row/column of file_path and write a clean,
    macro-free .xlsx copy at output_path with identical values.

    Returns a per-sheet report dict: {sheet_name: {"rows":, "cols":, "non_empty_cells":}}

    Caveat: data_only=True returns Excel's last-*cached*-calculated value
    for formulas, not the live formula. If a cell was never calculated in
    real Excel (e.g. built by a script and never opened), that cache can
    be None — a limitation of reading formulas without an Excel engine,
    not something this function can fix.
    """
    src_wb = openpyxl.load_workbook(file_path, data_only=True, keep_vba=False)
    out_wb = openpyxl.Workbook()
    out_wb.remove(out_wb.active)  # drop the default blank sheet

    report = {}
    for sheet in src_wb.worksheets:
        fill_map = _merged_fill_map(sheet)

        # openpyxl sheet titles cap at 31 chars
        out_ws = out_wb.create_sheet(title=sheet.title[:31])

        max_row = sheet.max_row or 0
        max_col = sheet.max_column or 0
        non_empty = 0

        for row in range(1, max_row + 1):
            for col in range(1, max_col + 1):
                value = fill_map.get((row, col), sheet.cell(row=row, column=col).value)
                if value is not None:
                    non_empty += 1
                    out_ws.cell(row=row, column=col, value=value)

        report[sheet.title] = {
            "rows": max_row,
            "cols": max_col,
            "non_empty_cells": non_empty,
            "merged_ranges_flattened": len(sheet.merged_cells.ranges),
        }

    out_wb.save(output_path)
    src_wb.close()
    return report


def export_sheets_to_csv(clean_xlsx_path, out_dir):
    """
    Optional convenience: split a clean workbook into one CSV per sheet.
    Only ever called on our OWN clean output, never on the original
    supplier file, so no security concern using it freely.
    """
    import csv
    import os

    os.makedirs(out_dir, exist_ok=True)
    wb = openpyxl.load_workbook(clean_xlsx_path, data_only=True)
    written = []
    for sheet in wb.worksheets:
        safe_name = "".join(c if c.isalnum() else "_" for c in sheet.title)
        csv_path = os.path.join(out_dir, f"{safe_name}.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            for row in sheet.iter_rows(values_only=True):
                writer.writerow(["" if v is None else v for v in row])
        written.append(csv_path)
    wb.close()
    return written