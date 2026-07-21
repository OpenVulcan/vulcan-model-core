"use client"

import { useState } from "react"

import {
  Combobox,
  ComboboxContent,
  ComboboxEmpty,
  ComboboxInput,
  ComboboxItem,
  ComboboxList,
} from "@/components/ui/combobox"
import { cn } from "@/lib/utils"

/**
 * Describes one selectable read-only combobox option.
 * 描述只读组合框中的一个可选项。
 */
export interface ReadonlyComboboxOption {
  /**
   * Stores the stable value submitted to the caller.
   * 保存提交给调用方的稳定值。
   */
  value: string
  /**
   * Stores the human-readable option label.
   * 保存供用户阅读的选项标签。
   */
  label: string
  /**
   * Indicates whether this option cannot be selected.
   * 指示该选项是否不可选择。
   */
  disabled?: boolean
}

/**
 * Configures a selection-only combobox that does not accept typed input.
 * 配置不接受键盘文本输入、仅允许选择的组合框。
 */
export interface ReadonlyComboboxProps {
  /**
   * Supplies the controlled selected value.
   * 提供受控的已选值。
   */
  value?: string
  /**
   * Supplies the initial value for an uncontrolled combobox.
   * 提供非受控组合框的初始值。
   */
  defaultValue?: string
  /**
   * Receives a newly selected non-null value.
   * 接收新选择的非空值。
   */
  onValueChange?: (value: string) => void
  /**
   * Provides the complete selectable option set.
   * 提供完整的可选项集合。
   */
  options: readonly ReadonlyComboboxOption[]
  /**
   * Displays guidance when no value is selected.
   * 在尚未选择值时显示提示文本。
   */
  placeholder?: string
  /**
   * Displays feedback when the option set is empty.
   * 在选项集合为空时显示反馈文本。
   */
  emptyText?: string
  /**
   * Associates the combobox input with an external label.
   * 将组合框输入框与外部标签关联。
   */
  id?: string
  /**
   * Provides an accessible label when no visible label is associated.
   * 在没有关联可见标签时提供无障碍名称。
   */
  ariaLabel?: string
  /**
   * Prevents all selection interactions when true.
   * 为真时禁止所有选择交互。
   */
  disabled?: boolean
  /**
   * Extends the combobox input container styles.
   * 扩展组合框输入容器样式。
   */
  className?: string
  /**
   * Controls the preferred popup side.
   * 控制弹出列表的首选方向。
   */
  contentSide?: "top" | "bottom" | "left" | "right" | "inline-start" | "inline-end"
  /**
   * Controls popup alignment relative to the input.
   * 控制弹出列表相对输入框的对齐方式。
   */
  contentAlign?: "start" | "center" | "end"
}

/**
 * Renders a shadcn combobox as a strict selection-only dropdown.
 * 将 shadcn 组合框渲染为严格的只选下拉框。
 *
 * @param props - Read-only combobox state, options, and presentation settings.
 * @param props - 只读组合框的状态、选项和展示设置。
 * @returns A read-only input with an interactive option popup.
 * @returns 一个带交互选项弹层的只读输入框。
 */
export function ReadonlyCombobox({
  value,
  defaultValue,
  onValueChange,
  options,
  placeholder,
  emptyText = "No items found.",
  id,
  ariaLabel,
  disabled = false,
  className,
  contentSide = "bottom",
  contentAlign = "start",
}: ReadonlyComboboxProps) {
  // Tracks popup visibility so a normal click opens the read-only input in browsers and tests.
  // 跟踪弹层可见性，使普通点击在浏览器和测试中都能打开只读输入框。
  const [open, setOpen] = useState(false)

  return (
    <Combobox
      items={options.map((option) => option.value)}
      value={value ?? undefined}
      defaultValue={defaultValue}
      disabled={disabled}
      open={open}
      onOpenChange={setOpen}
      itemToStringLabel={(optionValue) =>
        options.find((option) => option.value === optionValue)?.label ?? optionValue
      }
      onValueChange={(nextValue) => {
        if (nextValue !== null) onValueChange?.(nextValue)
      }}
    >
      <ComboboxInput
        id={id}
        aria-label={ariaLabel}
        className={cn("w-full", className)}
        placeholder={placeholder}
        disabled={disabled}
        readOnly
        showClear={false}
        onClick={() => {
          if (!disabled) setOpen(true)
        }}
      />
      <ComboboxContent side={contentSide} align={contentAlign}>
        <ComboboxEmpty>{emptyText}</ComboboxEmpty>
        <ComboboxList>
          {(optionValue) => {
            const option = options.find((candidate) => candidate.value === optionValue)

            if (!option) return null

            return (
              <ComboboxItem
                key={option.value}
                value={option.value}
                disabled={option.disabled}
              >
                {option.label}
              </ComboboxItem>
            )
          }}
        </ComboboxList>
      </ComboboxContent>
    </Combobox>
  )
}
