import type { RestoreTestsTableProps } from "../../types/ui";

export const RestoreTestsTable = ({ rows }: RestoreTestsTableProps) => (
    <table>
        <thead>
            <tr>
                <th>occurred_at</th>
                <th>result</th>
                <th>sample_count</th>
                <th>duration_ms</th>
                <th>trigger</th>
            </tr>
        </thead>
        <tbody>
            {rows.map((row) => (
                <tr
                    key={`${row.occurred_at}-${row.sample_count}`}
                    class={row.result === "success" ? undefined : "row--failure"}
                >
                    <td>{row.occurred_at}</td>
                    <td>{row.result}</td>
                    <td>{row.sample_count}</td>
                    <td>{row.duration_ms}</td>
                    <td>{row.trigger ?? "-"}</td>
                </tr>
            ))}
        </tbody>
    </table>
);
