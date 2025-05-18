package com.stephensalano.fileflow_api.entities;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class FollowId implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    // These field names must match exactly with the corresponding fields in the Follow entity
    private UUID followerAccount;   // matches the followerAccount field in Follow
    private UUID followingAccount;  // matches the followingAccount field in Follow

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FollowId that = (FollowId) o;
        return Objects.equals(followerAccount, that.followerAccount) &&
                Objects.equals(followingAccount, that.followingAccount);
    }

    @Override
    public int hashCode() {
        return Objects.hash(followerAccount, followingAccount);
    }
}
