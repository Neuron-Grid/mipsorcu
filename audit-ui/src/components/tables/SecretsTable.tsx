import type { SecretsTableProps } from "@/types/ui";

export const SecretsTable = ({ rows }: SecretsTableProps) => (
    <table>
        <thead>
            <tr>
                <th>secret_id</th>
                <th>owner_user_id</th>
                <th>classification</th>
                <th>current_version_id</th>
                <th>created_at</th>
                <th>updated_at</th>
            </tr>
        </thead>
        <tbody>
            {rows.map((row) => (
                <tr key={row.secret_id}>
                    <td>{row.secret_id}</td>
                    <td>{row.owner_user_id}</td>
                    <td>{row.classification}</td>
                    <td>{row.current_version_id ?? "-"}</td>
                    <td>{row.secret_created_at}</td>
                    <td>{row.secret_updated_at}</td>
                </tr>
            ))}
        </tbody>
    </table>
);
