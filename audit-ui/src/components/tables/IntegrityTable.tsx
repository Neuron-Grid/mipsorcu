import type { IntegrityTableProps } from "../../types/ui";

export const IntegrityTable = ({ rows }: IntegrityTableProps) => (
    <table>
        <thead>
            <tr>
                <th>chain_id</th>
                <th>last_sequence_no</th>
                <th>last_entry_hash</th>
                <th>updated_at</th>
            </tr>
        </thead>
        <tbody>
            {rows.map((row) => (
                <tr key={row.chain_id}>
                    <td>{row.chain_id}</td>
                    <td>{row.last_sequence_no}</td>
                    <td>{row.last_entry_hash}</td>
                    <td>{row.chain_state_updated_at}</td>
                </tr>
            ))}
        </tbody>
    </table>
);
