import { safeJsonText } from "@/redaction";
import type { AuditEventsTableProps } from "@/types/ui";

export const AuditEventsTable = ({ rows }: AuditEventsTableProps) => (
    <table>
        <thead>
            <tr>
                <th>occurred_at</th>
                <th>action</th>
                <th>result</th>
                <th>actor_user_id</th>
                <th>target_secret_id</th>
                <th>metadata</th>
            </tr>
        </thead>
        <tbody>
            {rows.map((row) => (
                <tr
                    key={row.audit_event_id}
                    class={row.result === "failure" ? "row--failure" : undefined}
                >
                    <td>{row.occurred_at}</td>
                    <td>{row.action}</td>
                    <td>{row.result}</td>
                    <td>{row.actor_user_id ?? "-"}</td>
                    <td>{row.target_secret_id ?? "-"}</td>
                    <td>
                        <pre>{safeJsonText(row.metadata_json)}</pre>
                    </td>
                </tr>
            ))}
        </tbody>
    </table>
);
