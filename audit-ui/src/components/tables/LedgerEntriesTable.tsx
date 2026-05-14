import { safeJsonText } from "@/redaction";
import type { LedgerEntriesTableProps } from "@/types/ui";

export const LedgerEntriesTable = ({ rows }: LedgerEntriesTableProps) => (
    <table>
        <thead>
            <tr>
                <th>sequence_no</th>
                <th>entry_type</th>
                <th>result</th>
                <th>error_code</th>
                <th>entry_hash</th>
                <th>signature_key_version</th>
                <th>payload</th>
            </tr>
        </thead>
        <tbody>
            {rows.map((row) => (
                <tr
                    key={row.ledger_entry_id}
                    class={
                        row.result === "failure" || row.error_code !== null
                            ? "row--failure"
                            : undefined
                    }
                >
                    <td>{row.sequence_no}</td>
                    <td>{row.entry_type}</td>
                    <td>{row.result}</td>
                    <td>{row.error_code ?? "-"}</td>
                    <td>{row.entry_hash}</td>
                    <td>{row.signature_key_version}</td>
                    <td>
                        <pre>{safeJsonText(row.payload)}</pre>
                    </td>
                </tr>
            ))}
        </tbody>
    </table>
);
