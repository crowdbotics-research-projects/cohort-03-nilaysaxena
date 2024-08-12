"""Update models with correct table names and relationshipss

Revision ID: fb557d2d3ecd
Revises: 11d38e92dde8
Create Date: 2024-08-12 11:11:32.979629

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "fb557d2d3ecd"
down_revision = "11d38e92dde8"
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column("subscriptions", sa.Column("price", sa.Float(), nullable=True))
    op.drop_column("subscriptions", "price_at_renewal")
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column(
        "subscriptions",
        sa.Column(
            "price_at_renewal",
            sa.DOUBLE_PRECISION(precision=53),
            autoincrement=False,
            nullable=True,
        ),
    )
    op.drop_column("subscriptions", "price")
    # ### end Alembic commands ###
