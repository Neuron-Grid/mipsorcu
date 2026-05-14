import type { FailuresTableProps } from "../../types/ui";

export const FailuresTable = ({ rows }: FailuresTableProps) => (
    <table>
        <thead>
            <tr>
                <th>occurred_at</th>
                <th>source</th>
                <th>code</th>
                <th>sequence_no</th>
            </tr>
        </thead>
        <tbody>
            {rows.map((row) => (
                <tr key={`${row.source}-${row.code}-${row.occurred_at}`} class="row--failure">
                    <td>{row.occurred_at}</td>
                    <td>{row.source}</td>
                    <td>{row.code}</td>
                    <td>{row.sequence_no ?? "-"}</td>
                </tr>
            ))}
        </tbody>
    </table>
);
