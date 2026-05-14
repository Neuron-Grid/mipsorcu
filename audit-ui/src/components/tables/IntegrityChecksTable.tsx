import type { IntegrityChecksTableProps } from "../../types/ui";

export const IntegrityChecksTable = ({ rows }: IntegrityChecksTableProps) => (
    <table>
        <thead>
            <tr>
                <th>occurred_at</th>
                <th>result</th>
                <th>violation_count</th>
                <th>checked counts</th>
                <th>duration_ms</th>
                <th>trigger</th>
            </tr>
        </thead>
        <tbody>
            {rows.map((row) => (
                <tr
                    key={`${row.occurred_at}-${row.checked_audit_event_count}`}
                    class={
                        row.result !== "success" || row.violation_count > 0
                            ? "row--failure"
                            : undefined
                    }
                >
                    <td>{row.occurred_at}</td>
                    <td>{row.result}</td>
                    <td>{row.violation_count}</td>
                    <td>
                        {`audit_events=${row.checked_audit_event_count}, secrets=${row.checked_secret_count}, secret_versions=${row.checked_secret_version_count}`}
                    </td>
                    <td>{row.duration_ms}</td>
                    <td>{row.trigger ?? "-"}</td>
                </tr>
            ))}
        </tbody>
    </table>
);
