import { fireEvent, render, screen } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"

import { ReadonlyCombobox } from "@/components/ui/readonly-combobox"

describe("ReadonlyCombobox", () => {
  /** Verifies that the input is immutable while options remain selectable. */
  /** 验证输入内容不可编辑，同时选项仍然可以选择。 */
  it("allows selection without allowing text entry", () => {
    // Records the value emitted by an explicit option selection.
    // 记录显式选择选项时发出的值。
    const onValueChange = vi.fn()

    render(
      <ReadonlyCombobox
        ariaLabel="Protocol"
        onValueChange={onValueChange}
        options={[
          { value: "openai.chat", label: "OpenAI Chat Completions" },
          { value: "openai.responses", label: "OpenAI Responses" },
        ]}
      />,
    )

    // Resolves the actual text input exposed by the Base UI combobox.
    // 获取 Base UI 组合框实际公开的文本输入框。
    const input = screen.getByRole("combobox", { name: "Protocol" })

    expect(input).toHaveAttribute("readonly")

    fireEvent.click(input)
    fireEvent.click(screen.getByRole("option", { name: "OpenAI Responses" }))

    expect(onValueChange).toHaveBeenCalledWith("openai.responses")
  })
})
