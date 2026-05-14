import type { MonthlyDigestsTableProps } from "../../types/ui";

export const MonthlyDigestsTable = ({ rows }: MonthlyDigestsTableProps) => (
    <table>
        <thead>
            <tr>
                <th>target_year_month</th>
                <th>sequence_no</th>
                <th>range</th>
                <th>entry_count</th>
                <th>digest_hash</th>
            </tr>
        </thead>
        <tbody>
            {rows.map((row) => (
                <tr key={`${row.target_year_month}-${row.sequence_no}`}>
                    <td>{row.target_year_month}</td>
                    <td>{row.sequence_no}</td>
                    <td>{`${row.start_sequence_no}..${row.end_sequence_no}`}</td>
                    <td>{row.entry_count}</td>
                    <td>{row.digest_hash}</td>
                </tr>
            ))}
        </tbody>
    </table>
);
